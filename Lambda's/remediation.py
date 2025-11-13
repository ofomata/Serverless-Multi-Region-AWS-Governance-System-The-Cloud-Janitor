import boto3
import os
import uuid
import json
import logging
from datetime import datetime, date, time
from json import JSONEncoder
from botocore.exceptions import ClientError

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ddb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# --- Custom Encoder ---
class DateTimeEncoder(JSONEncoder):
    """
    Custom JSON encoder to handle datetime objects by converting them to ISO format strings.
    """
    def default(self, obj):
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)
# ----------------------

def log_to_dynamodb(item):
    """
    Logs the remediation event to DynamoDB using the custom encoder.
    """
    try:
        table = ddb.Table(os.environ['DYNAMO_TABLE_NAME'])
        table.put_item(Item=json.loads(json.dumps(item, cls=DateTimeEncoder)))
    except Exception as e:
        logger.error(f"FATAL ERROR logging remediation to DynamoDB: {e.__class__.__name__}: {e}")

# Helper to get the key value
def get_resource_id_value(r):
    return r.get('resource_id', r.get('bucket', r.get('user', '')))


def remediate_ec2(item):
    ec2 = boto3.client('ec2', region_name=item['region'])
    iid = item['resource_id']
    logger.info(f"Attempting to STOP EC2 instance {iid}...")
    try:
        ec2.stop_instances(InstanceIds=[iid])
        return {'resource_type': 'EC2', 'resource_id': iid, 'region': item['region'], 'action': 'stopped', 'result': 'ok'}
    except Exception as e:
        logger.error(f"EC2 stop failed for {iid}: {e}")
        return {'resource_type': 'EC2', 'resource_id': iid, 'region': item['region'], 'action': 'stop_failed', 'error': str(e)}

def remediate_rds(item):
    rds = boto3.client('rds', region_name=item['region'])
    db_id = item['resource_id']
    logger.info(f"Attempting to DELETE RDS instance {db_id}...")
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=db_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True
        )
        return {'resource_type': 'RDS', 'resource_id': db_id, 'region': item['region'], 'action': 'deleted_without_snapshot', 'result': 'ok'}
    except Exception as e:
        logger.error(f"RDS delete failed for {db_id}: {e}")
        return {'resource_type': 'RDS', 'resource_id': db_id, 'region': item['region'], 'action': 'delete_failed', 'result': 'failed', 'error': str(e)}


def remediate_eip(item):
    """Remediation: Release the unattached Elastic IP address."""
    ec2 = boto3.client('ec2', region_name=item['region'])
    allocation_id = item['resource_id']
    
    logger.info(f"Attempting to RELEASE EIP {allocation_id}...")
    try:
        ec2.release_address(AllocationId=allocation_id)
        
        return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'action': 'released', 'result': 'ok'}
        
    except Exception as e:
        logger.error(f"EIP release failed for {allocation_id}: {e}")
        return {'resource_type': 'EIP', 'resource_id': allocation_id, 'region': item['region'], 'action': 'release_failed', 'result': 'failed', 'error': str(e)}

def remediate_s3(item):
    s3 = boto3.client('s3', region_name=item.get('region'))
    name = item['bucket']
    logger.info(f"Attempting to BLOCK PUBLIC ACCESS for S3 bucket {name}...")
    results = {'resource_type': 'S3', 'bucket': name, 'region': item.get('region')}
    try:
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        results['action'] = 'enabled_public_access_block'
        results['result'] = 'ok'
    except Exception as e:
        logger.error(f"S3 PAB failed for {name}: {e}")
        results['error'] = str(e)
        results['result'] = 'failed'
    return results

def remediate_iam(item):
    iam = boto3.client('iam')
    uname = item['user']
    logger.info(f"Attempting to TAG IAM user {uname} for MFA enforcement...")
    try:
        iam.tag_user(UserName=uname, Tags=[{'Key': 'Governance', 'Value': 'MFA_REQUIRED'}])
        return {'resource_type': 'IAM', 'user': uname, 'region': 'global', 'action': 'tagged_mfa_required', 'result': 'ok'}
    except Exception as e:
        logger.error(f"IAM tagging failed for {uname}: {e}")
        return {'resource_type': 'IAM', 'user': uname, 'region': 'global', 'action': 'tag_failed', 'result': 'failed', 'error': str(e)}


def create_sns_message(results):
    """
    Generates a plain-text summary message, then wraps it in the JSON required by 
    AWS Chatbot/Amazon Q.
    """
    successful_actions = [r for r in results if r.get('result') == 'ok']
    failed_actions = [r for r in results if r.get('result') != 'ok']
    
    total = len(results)
    success_count = len(successful_actions)
    fail_count = len(failed_actions)
    
    # 1. Subject Line
    subject = f"AWS Governance Remediation Run: {success_count} Succeeded, {fail_count} Failed"
    
    # 2. Plain Text Message Body (used as the 'description' in the JSON payload)
    message_body = f"--- AWS GOVERNANCE AUTOMATION REPORT ---\n\n"
    message_body += f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    message_body += f"Total Resources Targeted: {total}\n"
    message_body += f"Successful Remediation Actions: {success_count}\n"
    message_body += f"Failed Remediation Actions: {fail_count}\n"
    message_body += "\n"
    
    if successful_actions:
        message_body += "--- SUCCESSFUL ACTIONS ---\n"
        for r in successful_actions:
            resource_id = get_resource_id_value(r)
            message_body += f"- [{r['resource_type']}] {resource_id} in {r.get('region', 'global')} was **{r['action']}**.\n"
        message_body += "\n"
        
    if failed_actions:
        message_body += "--- FAILED ACTIONS ---\n"
        for r in failed_actions:
            resource_id = get_resource_id_value(r)
            error_details = r.get('error', 'Unknown Error')
            message_body += f"- [!! {r['resource_type']}] {resource_id} in {r.get('region', 'global')} **FAILED**: {error_details}\n"
        message_body += "\n"
        message_body += "Action required: Review Lambda logs and resource permissions for failed items."
    
    # 3. Wrap the message in the AWS Chatbot Custom Notification Payload
    chatbot_payload = {
        "version": "1.0",
        "source": "custom",
        "content": {
            "description": message_body 
        }
    }
        
    return subject, json.dumps(chatbot_payload) # Return the JSON string

def lambda_handler(event, context):
    results = []
    
    # The input from Recheck is the list of STILL NON-COMPLIANT resources
    violations_to_remediate = event.get('recheck_results', [])
    
    logger.info(f"Starting Remediation on {len(violations_to_remediate)} resources.")

    for r in violations_to_remediate:
        
        if r.get('still_non_compliant'): 
            t = r.get('resource_type')
            
            if t == 'EC2':
                results.append(remediate_ec2(r))
            elif t == 'RDS': 
                results.append(remediate_rds(r))
            elif t == 'EIP': 
                results.append(remediate_eip(r))
            elif t == 'S3':
                results.append(remediate_s3(r))
            elif t == 'IAM':
                results.append(remediate_iam(r))
            else:
                 logger.warning(f"Unknown resource type received for remediation: {t}")

    # Log results to DynamoDB
    for r in results:
        resource_id = get_resource_id_value(r)
        
        log_item = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(), 
            'resource_type': r['resource_type'],
            'resource_name': resource_id,
            'region': r.get('region', 'global'),
            'action': 'remediated' if r.get('result') == 'ok' else 'remediation_failed',
            'details': json.dumps(r, cls=DateTimeEncoder),
            'resource_identifier': resource_id 
        }
        log_to_dynamodb(log_item)
        
    # Publish single summary email
    if results:
        subject, sns_message_payload = create_sns_message(results)
        
        try:
            sns.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'], 
                Subject=subject, 
                Message=sns_message_payload # Sends JSON string for Chatbot
            )
            logger.info('SNS notification (Chatbot format) published successfully.')
        except Exception as e:
            logger.error('SNS publish failed: %s', e)

    return {'remediation_results': results}