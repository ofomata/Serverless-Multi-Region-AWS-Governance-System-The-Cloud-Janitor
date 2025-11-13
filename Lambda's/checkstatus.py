import boto3
import os
import json
import logging
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone
from json import JSONEncoder

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- DateTimeEncoder defined locally to resolve 'No module named 'discovery'' ---
class DateTimeEncoder(JSONEncoder):
    """
    Custom JSON encoder to handle datetime objects by converting them to ISO format strings.
    This resolves JSON serialization errors when working with DynamoDB timestamps.
    """
    def default(self, obj):
        if isinstance(obj, (datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)
# ----------------------------------------------------------------------------------

ddb_lock = boto3.resource('dynamodb')
LOCK_TABLE_NAME = os.environ['LOCK_TABLE_NAME']
lock_table = ddb_lock.Table(LOCK_TABLE_NAME)

# SET FOR TESTING: 200 seconds for current manual test grace period
LOCK_DURATION_SECONDS = 200

def get_resource_id_value(v):
    return v.get('resource_id', v.get('bucket', v.get('user', '')))

def attempt_lock(resource_id):
    if not resource_id: return False

    expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=LOCK_DURATION_SECONDS)
    expires_at = int(expiry_dt.timestamp())
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    try:
        lock_table.put_item(
            Item={
                'resource_identifier': resource_id,
                'locked_by': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'unknown'),
                'expires_at': expires_at,
                'lock_time': str(datetime.now(timezone.utc))
            },
            ConditionExpression='attribute_not_exists(resource_identifier) OR expires_at < :current_time',
            ExpressionAttributeValues={
                ':current_time': current_time
            }
        )
        logger.info(f"✅ Lock acquired for resource: {resource_id}. Proceeding.")
        return True 
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.info(f"❌ Active lock already held for resource: {resource_id}. Skipping.")
            return False
        else:
            logger.error(f"DynamoDB Lock Error: {e}")
            # Fail safe: if a non-conditional error occurs, treat it as success to proceed.
            return True 

def lambda_handler(event, context):
    logger.info("Starting CheckStatus for new violations using TTL-aware Transactional Lock.")
    
    violations = event.get('violations', []) 
    
    if not violations:
        return {'new_violations': [], 'new_violation_count': 0}
    
    new_violations = []
    for v in violations:
        resource_id = get_resource_id_value(v)
        if attempt_lock(resource_id): 
            new_violations.append(v)
    
    logger.info(f"Total violations found: {len(violations)}. New/unhandled: {len(new_violations)}")
    
    return {
        'new_violations': new_violations,
        'new_violation_count': len(new_violations)
    }