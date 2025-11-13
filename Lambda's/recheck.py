import boto3
import os
import datetime
import json
import uuid
import logging
from botocore.exceptions import ClientError
from json import JSONEncoder
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- DateTimeEncoder defined locally to resolve 'No module named 'discovery'' ---
class DateTimeEncoder(JSONEncoder):
    """
    Custom JSON encoder to handle datetime objects by converting them to ISO format strings.
    """
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)
# ----------------------------------------------------------------------------------

ddb = boto3.resource('dynamodb')

# Initialize the Snooze Table outside the handler
try:
    snooze_table = ddb.Table(os.environ['SNOOZE_TABLE_NAME'])
except KeyError:
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
            ProjectionExpression='snooze_until' 
        )
        item = response.get('Item')
        
        if item:
            # Check if snooze_until exists and is in the future
            if 'snooze_until' in item and int(item['snooze_until']) > current_time_epoch:
                snooze_ts = int(item['snooze_until'])
                snooze_time = datetime.datetime.fromtimestamp(snooze_ts).isoformat()
                logger.info(f"🛑 Resource {resource_id} is snoozed until {snooze_time}. Skipping recheck and remediation.")
                return True
    except Exception as e:
        logger.error(f"❌ Failed to check snooze status for {resource_id}: {e}")
        # Fail safe: If check fails, proceed with recheck
        return False
    
    return False

def get_resource_id_value(r):
    """Helper to safely get the main identifier for a resource."""
    return r.get('resource_id', r.get('bucket', r.get('user', '')))

def log_to_dynamodb(item):
    """
    Logs the recheck summary to DynamoDB using the custom encoder.
    """
    try:
        table = ddb.Table(os.environ['DYNAMO_TABLE_NAME'])
        table.put_item(Item=json.loads(json.dumps(item, cls=DateTimeEncoder)))
    except Exception as e:
        logger.error(f"FATAL ERROR logging recheck to DynamoDB: {e.__class__.__name__}: {e}")

# Recheck functions for existing resource types
def recheck_ec2(item):
    """Checks if an EC2 instance previously flagged as idle is still running."""
    logger.info(f"Rechecking EC2 {item['resource_id']} in {item['region']}...")
    ec2 = boto3.client('ec2', region_name=item['region'])
    iid = item['resource_id']
    try:
        inst = ec2.describe_instances(InstanceIds=[iid])
        instance = inst['Reservations'][0]['Instances'][0]
        state = instance['State']['Name']
        
        still_non_compliant = state == 'running'
        
        return {'resource_type': 'EC2', 'resource_id': iid, 'region': item['region'], 'still_non_compliant': still_non_compliant, 'status': state}
    except ClientError as e:
        return {'resource_type': 'EC2', 'resource_id': iid, 'region': item['region'], 'error': str(e), 'still_non_compliant': False}
    except Exception as e:
        return {'resource_type': 'EC2', 'resource_id': iid, 'region': item['region'], 'error': str(e), 'still_non_compliant': True}


def recheck_rds(item):
    """Checks if the RDS instance is still available (i.e., not deleted/stopped/modified by owner)."""
    logger.info(f"Rechecking RDS {item['resource_id']} in {item['region']}...")
    rds = boto3.client('rds', region_name=item['region'])
    db_id = item['resource_id']
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        status = resp['DBInstances'][0]['DBInstanceStatus']
        still_non_compliant = status == 'available'
        return {'resource_type': 'RDS', 'resource_id': db_id, 'region': item['region'], 'still_non_compliant': still_non_compliant, 'status': status}
    except ClientError as e:
        return {'resource_type': 'RDS', 'resource_id': db_id, 'region': item['region'], 'still_non_compliant': False, 'error': str(e)}
    except Exception as e:
        return {'resource_type': 'RDS', 'resource_id': db_id, 'region': item['region'], 'still_non_compliant': True, 'error': str(e)}


def recheck_eip(item):
    """Checks if the Elastic IP address is still unattached."""
    logger.info(f"Rechecking EIP {item['resource_id']} in {item['region']}...")
    ec2 = boto3.client('ec2', region_name=item['region'])
    allocation_id = item['resource_id']
    try:
        resp = ec2.describe_addresses(AllocationIds=[allocation_id])
        
        if not resp['Addresses']:
             return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'still_non_compliant': False}
             
        still_non_compliant = 'AssociationId' not in resp['Addresses'][0]
        
        return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'still_non_compliant': still_non_compliant}
    except ClientError as e:
        return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'still_non_compliant': False, 'error': str(e)}
    except Exception as e:
        return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'still_non_compliant': True, 'error': str(e)}


def recheck_s3(item):
    """Checks if the S3 bucket is still public."""
    logger.info(f"Rechecking S3 {item['bucket']} in {item['region']}...")
    s3 = boto3.client('s3', region_name=item['region'])
    name = item['bucket']
    violations = []
    
    try:
        # Check Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            pab_cfg = pab['PublicAccessBlockConfiguration']
            if not all(pab_cfg.values()):
                violations.append('public_access_block_disabled')
        except s3.exceptions.ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                violations.append('no_public_access_block')

        # Check ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get('Grants', []):
                gr = g.get('Grantee', {})
                if gr.get('URI') in ["http://acs.amazonaws.com/groups/global/AllUsers",
                                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]:
                    violations.append('public_via_acl')
                    break
        except Exception:
            pass

        # Check Policy
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            policy = json.loads(pol.get('Policy', '{}'))
            for stmt in policy.get('Statement', []):
                eff = stmt.get('Effect', '')
                princ = stmt.get('Principal')
                if eff == 'Allow' and (princ == "*" or princ == {"AWS": "*"}):
                    violations.append('public_via_policy')
                    break
        except Exception:
            pass

        still_non_compliant = len(violations) > 0
        return {'resource_type': 'S3', 'bucket': name, 'region': item['region'], 'still_non_compliant': still_non_compliant, 'violations': violations}

    except ClientError as e:
        return {'resource_type': 'S3', 'bucket': name, 'region': item['region'], 'still_non_compliant': False, 'error': str(e)}
    except Exception as e:
        return {'resource_type': 'S3', 'bucket': name, 'region': item['region'], 'still_non_compliant': True, 'error': str(e)}

def recheck_iam(item):
    """Checks if the IAM user still lacks an MFA device."""
    logger.info(f"Rechecking IAM user {item['user']}...")
    iam = boto3.client('iam')
    uname = item['user']
    try:
        mfas = iam.list_mfa_devices(UserName=uname).get('MFADevices', [])
        still_non_compliant = len(mfas) == 0
        return {'resource_type': 'IAM', 'user': uname, 'region': 'global', 'still_non_compliant': still_non_compliant}
    except ClientError as e:
        return {'resource_type': 'IAM', 'user': uname, 'region': 'global', 'still_non_compliant': False, 'error': str(e)}
    except Exception as e:
        return {'resource_type': 'IAM', 'user': uname, 'region': 'global', 'still_non_compliant': True, 'error': str(e)}


def lambda_handler(event, context):
    violations = event.get('new_violations', event.get('violations', [])) 
    execution_id = event.get('execution_id', 'N/A')
    results = []
    
    logger.info(f"Starting Recheck on {len(violations)} resources from the Notifier output.")

    for v in violations:
        resource_id_to_check = get_resource_id_value(v)
        
        # Check for snooze FIRST
        if is_resource_snoozed(resource_id_to_check):
            # If snoozed, skip the recheck and DO NOT pass it to remediation (by not appending to results)
            continue 

        # If not snoozed, proceed with the recheck logic
        t = v.get('resource_type')
        if t == 'EC2':
            results.append(recheck_ec2(v))
        elif t == 'RDS': 
            results.append(recheck_rds(v))
        elif t == 'EIP': 
            results.append(recheck_eip(v))
        elif t == 'S3':
            results.append(recheck_s3(v))
        elif t == 'IAM':
            results.append(recheck_iam(v))

    still_non_compliant_count = sum(1 for r in results if r.get('still_non_compliant'))
    has_non_compliant = still_non_compliant_count > 0

    still_non_compliant_resources = [r for r in results if r.get('still_non_compliant')]
    affected_regions = list({r.get('region') for r in still_non_compliant_resources if r.get('region') and r.get('region') != 'global'})
    
    logger.info(f"Recheck complete. Total checked: {len(results)}. Still non-compliant: {still_non_compliant_count}.")

    log_to_dynamodb({
        'id': execution_id,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'execution_type': 'RECHECK_RUN',
        'resource_type': 'global',
        'resource_name': 'Recheck',
        'region': ', '.join(affected_regions) if affected_regions else 'global',
        'action': 'recheck', 
        'details': json.dumps({
            'checked': len(results),
            'still_non_compliant': still_non_compliant_count,
            'regions': affected_regions
        }, cls=DateTimeEncoder),
        'resource_identifier': 'RECHECK_RUN'
    })

    return {
        'recheck_results': still_non_compliant_resources,
        'has_non_compliant': has_non_compliant
    }