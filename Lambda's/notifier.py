import json
import os
import logging
import boto3
from datetime import datetime, date, time
from json import JSONEncoder
# New Imports for Slack Integration
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- DateTimeEncoder (Copied locally for packaging) ---
class DateTimeEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)
# -----------------------------------------------------

# --- GLOBAL INITIALIZATION FOR AWS AND SLACK ---
ddb = boto3.resource('dynamodb')
sm = boto3.client('secretsmanager')

# Variables loaded from environment
DYNAMO_TABLE_NAME = os.environ.get('DYNAMO_TABLE_NAME')
BOT_TOKEN_NAME = os.environ.get('BOT_TOKEN_NAME')
# Replace with the actual Slack channel ID
SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL_ID', '#governance-notifications')

# Slack client variable
SLACK_CLIENT = None

def get_slack_client():
    """Retrieves the Bot Token and initializes the Slack WebClient."""
    global SLACK_CLIENT

    if SLACK_CLIENT is None and BOT_TOKEN_NAME:
        try:
            # 1. Get Bot Token from Secrets Manager
            token_response = sm.get_secret_value(SecretId=BOT_TOKEN_NAME)
            token_data = json.loads(token_response['SecretString'])
            # Use the exact key name you defined inside the secret
            SLACK_BOT_TOKEN = token_data.get('BotUserOAuthToken')
            
            # 2. Initialize the client
            SLACK_CLIENT = WebClient(token=SLACK_BOT_TOKEN)
            logger.info("Slack WebClient initialized successfully.")
            
        except Exception as e:
            logger.error(f"FATAL ERROR: Failed to initialize Slack Client: {e}")
            SLACK_CLIENT = None
            
    return SLACK_CLIENT

def log_to_dynamodb(item):
    """Logs the notification event to DynamoDB."""
    try:
        table = ddb.Table(DYNAMO_TABLE_NAME)
        table.put_item(Item=json.loads(json.dumps(item, cls=DateTimeEncoder)))
    except Exception as e:
        logger.error(f"FATAL ERROR logging to DynamoDB: {e.__class__.__name__}: {e}")

def get_resource_id_value(r):
    """Helper to safely get the main identifier for a resource."""
    return r.get('resource_id', r.get('bucket', r.get('user', '')))

# === START: SLACK BLOCK KIT GENERATION ===
def create_slack_blocks(record):
    """
    Generates Slack Block Kit JSON objects for an interactive message with a Snooze button.
    """
    resource_id = get_resource_id_value(record)
    resource_type = record.get('resource_type', 'Unknown')
    policy_name = record.get('policy_name', 'N/A')
    
    # Value format for Snooze Handler: "RESOURCE_TYPE|RESOURCE_ID"
    snooze_value = f"{resource_type}|{resource_id}"
    
    slack_blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Governance Violation Detected"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Resource Type:*\n{resource_type}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Resource ID:*\n`{resource_id}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Policy Violated:*\n{policy_name}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Region:*\n{record.get('region', 'global')}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Reason: {record.get('reason', 'No specific reason provided.')}"
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Snooze for 30 Days 😴",
                        "emoji": True
                    },
                    "style": "primary",
                    "action_id": "snooze_button",
                    # This value is passed back to your API Gateway/Snooze Lambda
                    "value": snooze_value 
                }
            ]
        }
    ]
    
    return slack_blocks
# === END: SLACK BLOCK KIT GENERATION ====


def lambda_handler(event, context):
    
    # 1. Initialize Slack Client
    client = get_slack_client()
    if not client:
        logger.error("Skipping notification: Slack Client not initialized due to missing token.")
        return {'notified': False}
        
    # 2. Extract Violations
    violations = event.get('new_violations', event.get('violations', [])) 
    execution_id = event.get('execution_id', 'N/A')

    if not violations:
        logger.info("No new violations to notify.")
        return {'notified': False}

    logger.info(f"Preparing Slack notification for {len(violations)} new violations (Execution ID: {execution_id}).")

    notification_success_count = 0
    
    # 3. Process and Notify Each Violation
    for v in violations:
        resource_id = get_resource_id_value(v)
        slack_blocks = create_slack_blocks(v)
        
        slack_success = False
        try:
            # Send Interactive Slack Message
            client.chat_postMessage(
                channel=SLACK_CHANNEL,
                blocks=slack_blocks,
                text=f"Governance alert for {resource_id}." # Fallback text
            )
            slack_success = True
            notification_success_count += 1
            logger.info(f"Notification sent to Slack for resource: {resource_id}")
            
        except SlackApiError as e:
            logger.error(f"Slack API Error posting message for {resource_id}: {e.response['error']}")
        except Exception as e:
            logger.error(f"Error processing record {resource_id} for notification: {e}")

        # 4. Log the notification event
        log_item = {
            'id': resource_id + "-" + datetime.utcnow().isoformat(),
            'timestamp': datetime.utcnow().isoformat(),
            'resource_type': v.get('resource_type', 'Unknown'),
            'resource_name': resource_id,
            'region': v.get('region', 'global'),
            'action': 'notified_owner',
            'details': json.dumps({'message': 'Initial notification sent to Slack', 'slack_success': slack_success}, cls=DateTimeEncoder),
            'resource_identifier': resource_id
        }
        log_to_dynamodb(log_item)

    # 5. Return status
    return {
        'new_violations': violations, 
        'notified': notification_success_count > 0,
        'successful_notifications': notification_success_count
    }