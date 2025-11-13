import boto3
import os
import uuid
import datetime
import json
import logging
from botocore.exceptions import ClientError
import time 

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ddb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Initialize the Snooze Table outside the handler
try:
    snooze_table = ddb.Table(os.environ['SNOOZE_TABLE_NAME'])
except KeyError:
    # Handle the case where the environment variable is not set
    logger.error("SNOOZE_TABLE_NAME environment variable is not set. Snooze functionality is disabled.")
    snooze_table = None

def is_resource_snoozed(resource_id):
    """Checks if a resource has an active snooze entry in the GovernanceSnooze DynamoDB table."""
    if not resource_id or snooze_table is None:
        return False
    
    current_time_epoch = int(time.time())
    
    try:
        response = snooze_table.get_item(
            Key={'resource_id': resource_id},
            # ProjectionExpression will get only the attributes needed, speeding up the read.
            ProjectionExpression='snooze_until' 
        )
        item = response.get('Item')
        
        if item:
            # Check if snooze_until exists and is in the future
            if 'snooze_until' in item and int(item['snooze_until']) > current_time_epoch:
                # Use logger.debug/info to track skipped resources
                snooze_ts = int(item['snooze_until'])
                snooze_time = datetime.datetime.fromtimestamp(snooze_ts).isoformat()
                logger.info(f"🛑 Resource {resource_id} is snoozed until {snooze_time}. Skipping discovery.")
                return True
    except Exception as e:
        logger.error(f"❌ Failed to check snooze status for {resource_id}: {e}")
        # Fail safe: If check fails, assume NOT snoozed to ensure compliance is checked
        return False
    
    return False

# --- GLOBAL: Custom JSON Encoder to handle datetime objects ---
class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)
# ------------------------------------------------------------

# --- CONFIGURATION ---
REQUIRED_TAGS = ['Owner', 'Application'] 
# ---------------------

def get_all_regions():
    """Fetches all active AWS regions."""
    try:
        ec2 = boto3.client('ec2')
        regions = [r['RegionName'] for r in ec2.describe_regions(AllRegions=True)['Regions']]
        logger.info(f"🌍 Found {len(regions)} regions.")
        return regions
    except ClientError as e:
        logger.error(f"❌ Failed to describe regions: {e}")
        return []

def log_to_dynamodb(item):
    """Logs the summary of the discovery run using the custom encoder."""
    try:
        table = ddb.Table(os.environ['DYNAMO_TABLE_NAME'])
        table.put_item(Item=json.loads(json.dumps(item, cls=DateTimeEncoder)))
        logger.info(f"🗂️ Logged audit entry {item['id']} to DynamoDB.")
    except Exception as e:
        logger.error(f"❌ Failed to log to DynamoDB: {e}")

def scan_ec2():
    logger.info("🚀 Starting EC2 compliance scan...")
    violations = []
    error_count = 0
    
    for region in get_all_regions():
        ec2 = boto3.client('ec2', region_name=region)
        try:
            resp = ec2.describe_instances()
            regional_candidates = [] 
            
            for r in resp.get('Reservations', []):
                for i in r.get('Instances', []):
                    tags = {t['Key']: t['Value'] for t in i.get('Tags', [])}
                    state = i.get('State', {}).get('Name')
                    iid = i.get('InstanceId')
                    
                    if is_resource_snoozed(iid):
                        continue
                    
                    if state == 'running':
                        is_tagged_for_deletion = tags.get('Environment', '').lower() in ['testing', 'unused', 'dev']
                        missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]

                        metadata = {
                            'tags': tags, 
                            'state': state, 
                            'LaunchTime': i.get('LaunchTime') 
                        } 

                        if is_tagged_for_deletion:
                            regional_candidates.append({
                                'resource_type': 'EC2',
                                'resource_id': iid,
                                'region': region,
                                'reason': f"Tagged 'Environment': {tags.get('Environment')} (Immediate Cleanup)",
                                'metadata': metadata,
                                'needs_metric_check': False 
                            })
                        elif missing_tags:
                            regional_candidates.append({
                                'resource_type': 'EC2',
                                'resource_id': iid,
                                'region': region,
                                'reason': f"Missing required tags: {', '.join(missing_tags)}",
                                'metadata': metadata,
                                'needs_metric_check': True 
                            })
                            
            if regional_candidates:
                logger.info(f"📊 {len(regional_candidates)} EC2 candidates/violations found in {region}")
                violations.extend(regional_candidates)
            
        except ClientError as e:
            error_count += 1
            logger.error(f"❌ EC2 scan ClientError in {region}: {e}")
        except Exception as e:
            error_count += 1
            logger.error(f"❌ EC2 scan error in {region}: {e}")
            
    logger.info(f"📊 EC2 scan complete: {len(violations)} total candidates/violations | {error_count} regions failed.")
    return violations

def scan_rds():
    logger.info("💾 Starting RDS metric candidate scan...")
    candidates = []
    error_count = 0
    
    for region in get_all_regions():
        rds = boto3.client('rds', region_name=region)
        regional_candidates = [] 
        try:
            resp = rds.describe_db_instances()
            for db in resp.get('DBInstances', []):
                db_id = db['DBInstanceIdentifier']
                status = db['DBInstanceStatus']
                
                if is_resource_snoozed(db_id):
                    continue
                
                if status == 'available':
                    db_arn = db.get('DBInstanceArn')
                    tags_resp = rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = {t['Key']: t['Value'] for t in tags_resp.get('TagList', [])}
                    
                    missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]

                    metadata = {
                        'status': status, 
                        'tags': tags,
                        'InstanceCreateTime': db.get('InstanceCreateTime')
                    }
                    
                    if missing_tags:
                        regional_candidates.append({
                            'resource_type': 'RDS',
                            'resource_id': db_id,
                            'region': region,
                            'reason': f"Missing required tags: {', '.join(missing_tags)}",
                            'metadata': metadata,
                            'needs_metric_check': True 
                        })
            
            if regional_candidates:
                logger.info(f"📊 {len(regional_candidates)} RDS candidates found in {region}")
                candidates.extend(regional_candidates)
                
        except ClientError as e:
            error_count += 1
            logger.error(f"❌ RDS scan ClientError in {region}: {e}")
        except Exception as e:
            error_count += 1
            logger.error(f"❌ RDS scan error in {region}: {e}")
            
    logger.info(f"📊 RDS scan complete: {len(candidates)} total candidates/violations | {error_count} regions failed.")
    return candidates

def scan_eip():
    """Scans for allocated Elastic IPs that are currently unattached (cost violation)."""
    logger.info("🌐 Starting EIP unattached scan...")
    violations = []
    error_count = 0
    
    for region in get_all_regions():
        ec2 = boto3.client('ec2', region_name=region)
        try:
            # Describe all allocated EIPs
            response = ec2.describe_addresses()
            
            for address in response['Addresses']:
                allocation_id = address['AllocationId']
                
                if is_resource_snoozed(allocation_id):
                    continue
                
                # The violation: EIP is allocated but has no association ID (unattached).
                if 'AssociationId' not in address:
                    violations.append({
                        'resource_type': 'EIP',
                        'resource_id': allocation_id, # Use AllocationId for cleanup
                        'region': region,
                        'reason': f"Unattached Elastic IP ({address['PublicIp']}) is incurring cost.",
                        'metadata': {'PublicIp': address['PublicIp']},
                        'needs_metric_check': False # EIP is a static violation, no metric check needed
                    })
            
            if violations:
                logger.info(f"📊 {len(violations)} EIP violations found in {region}")
                
        except ClientError as e:
            error_count += 1
            logger.error(f"❌ EIP scan ClientError in {region}: {e}")
        except Exception as e:
            error_count += 1
            logger.error(f"❌ EIP scan error in {region}: {e}")
            
    logger.info(f"📊 EIP scan complete: {len(violations)} total violations | {error_count} regions failed.")
    return violations


def scan_s3():
    logger.info("🪣 Starting S3 compliance scan...")
    s3 = boto3.client('s3')
    violations = []
    try:
        for bucket in s3.list_buckets().get('Buckets', []):
            name = bucket['Name']
            
            if is_resource_snoozed(name):
                continue
            
            try:
                loc = s3.get_bucket_location(Bucket=name).get('LocationConstraint') or 'us-east-1'
            except Exception:
                loc = 'us-east-1'
            s3r = boto3.client('s3', region_name=loc)
            
            # --- Public Access Block check ---
            try:
                pab = s3r.get_public_access_block(Bucket=name)
                pab_cfg = pab['PublicAccessBlockConfiguration']
                if not all(pab_cfg.values()):
                    violations.append({'resource_type': 'S3', 'bucket': name, 'region': loc, 'reason': 'public_access_block_disabled', 'needs_metric_check': False})
            except s3r.exceptions.ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    violations.append({'resource_type': 'S3', 'bucket': name, 'region': loc, 'reason': 'no_public_access_block', 'needs_metric_check': False})
            
            # --- ACL check ---
            try:
                acl = s3r.get_bucket_acl(Bucket=name)
                for g in acl.get('Grants', []):
                    gr = g.get('Grantee', {})
                    if gr.get('URI') in [ "http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" ]:
                        violations.append({'resource_type': 'S3', 'bucket': name, 'region': loc, 'reason': 'public_via_acl', 'needs_metric_check': False})
                        break
            except Exception:
                pass
            
            # --- Policy check ---
            try:
                pol = s3r.get_bucket_policy(Bucket=name)
                policy = json.loads(pol.get('Policy', '{}'))
                for stmt in policy.get('Statement', []):
                    eff = stmt.get('Effect', '')
                    princ = stmt.get('Principal')
                    if eff == 'Allow' and (princ == "*" or princ == {"AWS": "*"}):
                        violations.append({'resource_type': 'S3', 'bucket': name, 'region': loc, 'reason': 'public_via_policy', 'needs_metric_check': False})
                        break
            except Exception:
                pass
                
        logger.info(f"📊 S3 scan complete: {len(violations)} violations found.")
    except Exception as e:
        logger.error(f"❌ S3 global scan error: {e}")
    return violations

def scan_iam():
    logger.info("🧍 Starting IAM compliance scan...")
    iam = boto3.client('iam')
    violations = []
    try:
        for u in iam.list_users().get('Users', []):
            username = u['UserName']
            
            if is_resource_snoozed(username):
                continue
            
            mfas = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
            if len(mfas) == 0:
                violations.append({'resource_type': 'IAM', 'user': username, 'region': 'global', 'reason': 'no_mfa', 'needs_metric_check': False})
        logger.info(f"📊 IAM scan complete: {len(violations)} users without MFA.")
    except Exception as e:
        logger.error(f"❌ IAM scan error: {e}")
    return violations


def lambda_handler(event, context):
    logger.info("🔍 Starting governance discovery process...")

    violations = []
    
    # Run all scans
    violations.extend(scan_ec2())
    violations.extend(scan_rds())
    violations.extend(scan_eip())
    violations.extend(scan_s3())
    violations.extend(scan_iam())
    

    exec_id = str(uuid.uuid4())
    
    # Log summary of the run
    audit_item = {
        'id': exec_id,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'resource_type': 'DiscoveryRun',
        'resource_name': 'Discovery',
        'region': 'global',
        'action': 'discovery',
        'details': json.dumps({'violations_count': len(violations), 'violations': violations}, cls=DateTimeEncoder),
        'resource_identifier': 'DISCOVERY_RUN'
    }
    log_to_dynamodb(audit_item)

    # 1. Serialize the list using the encoder.
    serialized_violations = json.dumps(violations, cls=DateTimeEncoder)
    # 2. De-serialize the list back into a pure Python list/dict structure
    #    that contains only primitive types (strings instead of datetime objects).
    clean_violations = json.loads(serialized_violations)
    
    logger.info(f"✅ Discovery complete: {len(violations)} total candidates/violations found.")
    
    # Return the clean list for the next Step Function step
    return {'execution_id': exec_id, 'violations': clean_violations}