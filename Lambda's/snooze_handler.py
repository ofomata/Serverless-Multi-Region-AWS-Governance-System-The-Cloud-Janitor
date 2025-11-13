import json
import os
import logging
import time
from datetime import datetime, timedelta
import urllib.parse
import base64 
# External libraries (must be packaged in the zip file: requests and slack_sdk)
from slack_sdk import WebClient
from slack_sdk.signature import SignatureVerifier
import boto3
import requests 

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- GLOBAL INITIALIZATION ---
DDB_CLIENT = boto3.client('dynamodb')
SM_CLIENT = boto3.client('secretsmanager')

SNOOZE_TABLE_NAME = os.environ.get('SNOOZE_TABLE_NAME')
SIGNING_SECRET_NAME = os.environ.get('SIGNING_SECRET_NAME')
BOT_TOKEN_NAME = os.environ.get('BOT_TOKEN_NAME')
SNOOZE_DURATION_DAYS = 30

SLACK_CLIENT = None
# VERIFIER is now initialized locally in the handler

def get_secrets_and_clients():
    """
    Retrieves secrets, initializes clients, and returns them for use in the handler.
    Returns the signing secret string and the initialized Slack client.
    """
    try:
        global SLACK_CLIENT
        
        # 1. Get Signing Secret (EXPECTING PLAIN TEXT STRING)
        logger.info(f"SM Secret Name for Signing Secret: {SIGNING_SECRET_NAME}") 
        secret_response = SM_CLIENT.get_secret_value(SecretId=SIGNING_SECRET_NAME)
        signing_secret = secret_response['SecretString']
        logger.info(f"Successfully retrieved Slack Signing Secret. Status: {bool(signing_secret)}")

        # 2. Get Bot Token (Expecting JSON key/value)
        logger.info(f"SM Secret Name for Bot Token: {BOT_TOKEN_NAME}") 
        token_response = SM_CLIENT.get_secret_value(SecretId=BOT_TOKEN_NAME)
        token_data = json.loads(token_response['SecretString'])
        bot_token = token_data.get('BotUserOAuthToken')
        logger.info(f"Successfully retrieved Slack Bot Token. Status: {bool(bot_token)}")

        # 3. Initialize Client (NO GLOBAL VERIFIER)
        SLACK_CLIENT = WebClient(token=bot_token)
        logger.info("Slack WebClient initialized successfully.")
        
        # 4. Final Sanity Check for existence
        if signing_secret and SLACK_CLIENT:
            logger.info("Final variable check passed. Configuration is successful.")
            # Return the signing_secret string and the SLACK_CLIENT object
            return signing_secret, SLACK_CLIENT 
        else:
             raise ValueError("One or more required secrets/clients were empty after initialization.")

    except Exception as e:
        logger.error(f"FATAL ERROR: Failed during secrets retrieval or client initialization: {e}")
        return None, None


def post_confirmation_message(resource_id, future_time_str, response_url, user_id):
    """Posts a confirmation message back to the user via the response_url."""
    try:
        requests.post(
            response_url, 
            json={
                "text": f"✅ *Snooze Confirmed:* Resource `{resource_id}` has been excluded from governance checks until *{future_time_str}*.",
                "response_type": "ephemeral"
            }
        )
        logger.info("Confirmation message posted via response_url.")
    except Exception as e:
        logger.error(f"Failed to post confirmation to Slack via response_url: {e}")


def handle_snooze_action(payload):
    """Processes the interactive button click payload and updates DynamoDB."""
    
    try:
        action = payload['actions'][0]
        snooze_value = action['value'] 
        resource_type, resource_id = snooze_value.split('|', 1) 
        user_id = payload['user']['id']
        response_url = payload['response_url']

        future_datetime = datetime.utcnow() + timedelta(days=SNOOZE_DURATION_DAYS)
        snooze_until_epoch = int(future_datetime.timestamp())
        future_time_str = future_datetime.strftime('%Y-%m-%d %H:%M UTC')

        ddb_item = {
            'resource_id': {'S': resource_id},
            'resource_type': {'S': resource_type},
            'snooze_until': {'N': str(snooze_until_epoch)},
            'snoozed_by': {'S': user_id},
            'timestamp': {'S': datetime.utcnow().isoformat()},
            'reason': {'S': f"Snoozed for {SNOOZE_DURATION_DAYS} days via Slack by <@{user_id}>"}
        }

        DDB_CLIENT.put_item(
            TableName=SNOOZE_TABLE_NAME,
            Item=ddb_item
        )
        
        logger.info(f"Successfully snoozed {resource_id} until {future_time_str}")
        post_confirmation_message(resource_id, future_time_str, response_url, user_id)

    except Exception as e:
        logger.error(f"Failed to process snooze action: {e}")
        if 'response_url' in payload:
            requests.post(
                payload['response_url'], 
                json={
                    "text": f"❌ Error processing snooze: {str(e)}", 
                    "response_type": "ephemeral"
                }
            )

# --- LAMBDA HANDLER ---
def lambda_handler(event, context):
    
    # Retrieve secrets and client
    signing_secret, slack_client = get_secrets_and_clients() 
    
    if not signing_secret or not slack_client:
        return {'statusCode': 500, 'body': json.dumps({"error": "Configuration Error."})}

    # Initialize verifier LOCALLY to ensure correct instance method behavior
    verifier = SignatureVerifier(signing_secret)
    
    # Handle API Gateway Base64 Encoding
    raw_body = event.get('body', '')
    
    if event.get('isBase64Encoded'):
        try:
            raw_body = base64.b64decode(raw_body).decode('utf-8')
            logger.info("Successfully Base64 decoded the request body for signature verification.")
        except Exception as e:
            logger.error(f"Failed to Base64 decode body: {e}")
            return {'statusCode': 400, 'body': json.dumps({"error": "Decoding Error."})}

    # --- INLINE SIGNATURE VERIFICATION ---
    
    timestamp = event['headers'].get('x-slack-request-timestamp')
    signature = event['headers'].get('x-slack-signature')
    
    if not timestamp or not signature:
        logger.error("Missing required Slack headers.")
        return {'statusCode': 401, 'body': json.dumps({"error": "Missing headers."})}

    
    if not verifier.is_valid_request(raw_body, event['headers']): 
        logger.error("Signature verification failed. Request is potentially forged.")
        return {'statusCode': 401, 'body': json.dumps({"error": "Signature verification failed."})}
        
    # Prevent replay attacks
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > 60 * 5: # 5 minutes window
         logger.warning("Timestamp verification failed. Request is too old (possible replay attack).")
         return {'statusCode': 401, 'body': json.dumps({"error": "Replay attack detected."})}

    logger.info("Slack request signature successfully verified.")

    # --- END INLINE SIGNATURE VERIFICATION ---
    
    # Parse the URL-encoded payload
    try:
        decoded_body = urllib.parse.unquote_plus(raw_body)
        payload_str = decoded_body.split('payload=')[1]
        payload = json.loads(payload_str)
        
    except Exception as e:
        logger.error(f"Failed to parse event body/payload: {e}")
        return {'statusCode': 400, 'body': json.dumps({"error": "Invalid payload format."})}
    
    # Check the payload type and handle action
    if payload.get('type') == 'block_actions':
        handle_snooze_action(payload)
        
        return {
            'statusCode': 200,
            'body': '' 
        }

    logger.info(f"Received unhandled payload type: {payload.get('type')}")
    return {'statusCode': 200, 'body': ''}