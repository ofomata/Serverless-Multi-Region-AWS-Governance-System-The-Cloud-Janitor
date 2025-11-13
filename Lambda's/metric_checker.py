import boto3
import json
import logging
import os 
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration loaded from Environment Variables ---
CHECK_PERIOD_UNIT = os.environ.get('CHECK_PERIOD_UNIT', 'DAYS').upper()
CHECK_PERIOD_VALUE = int(os.environ.get('CHECK_PERIOD_VALUE', 7))
# ADJUSTED AGGRESSIVE THRESHOLDS FOR TESTING:
EC2_IDLE_PERCENT = float(os.environ.get('EC2_IDLE_PERCENT', 5.0)) 
RDS_IDLE_CONNECTIONS = float(os.environ.get('RDS_IDLE_CONNECTIONS', 0.0))
# -----------------------------------------------------

def get_metric_statistics(client, namespace, metric_name, dimensions, start_time, end_time, period, statistics):
    """Fetches the metric statistics from CloudWatch."""
    try:
        response = client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=statistics
        )
        datapoints = response.get('Datapoints', [])
        logger.info(f"CloudWatch API returned {len(datapoints)} datapoints for {metric_name} on {dimensions[0]['Value']}.")
        return datapoints
    except Exception as e:
        logger.error(f"❌ CloudWatch API call failed for {metric_name} with dimensions {dimensions}: {str(e)}")
        return []

def calculate_time_window(period_unit, period_value):
    """Calculates start_time and the required CloudWatch period for the query."""
    end_time = datetime.now(timezone.utc)
    
    if period_unit == 'MINUTES':
        start_time = end_time - timedelta(minutes=period_value)
        # Use a 5-minute period (300 seconds) for fine-grained checks. This is for test purpose.
        period_seconds = 300 
    else: # Default to DAYS for production and long-term checks
        start_time = end_time - timedelta(days=period_value)
        # Use a 1-day period for long-term checks to reduce data points.
        period_seconds = 86400 
        
    return start_time, end_time, period_seconds

def check_ec2_metrics(resource, cloudwatch):
    """Checks EC2 CPU utilization against EC2_IDLE_PERCENT."""
    resource_id = resource['resource_id']
    logger.info(f"Checking EC2 metric for {resource_id}...")

    dimensions = [{'Name': 'InstanceId', 'Value': resource_id}]
    start_time, end_time, period_seconds = calculate_time_window(CHECK_PERIOD_UNIT, CHECK_PERIOD_VALUE)
    
    datapoints = get_metric_statistics(
        client=cloudwatch,
        namespace='AWS/EC2',
        metric_name='CPUUtilization',
        dimensions=dimensions,
        start_time=start_time,
        end_time=end_time,
        period=period_seconds,
        statistics=['Average']
    )

    is_idle = True
    if not datapoints:
        logger.warning(f"No EC2 CPU data found for {resource_id}. Cannot confirm idleness.")
        return False 

    for dp in datapoints:
        avg_cpu = dp.get('Average', 100)
        # Violation if CPU is always < EC2_IDLE_PERCENT
        if avg_cpu >= EC2_IDLE_PERCENT:
            logger.info(f"EC2 {resource_id} showed usage ({avg_cpu:.2f}% CPU). Marked compliant.")
            is_idle = False
            break

    if is_idle:
        resource['reason'] += f" | Metric: Avg CPU < {EC2_IDLE_PERCENT}% for {CHECK_PERIOD_VALUE} {CHECK_PERIOD_UNIT}"
        resource['is_metric_violation'] = True
        logger.info(f"🔴 EC2 {resource_id} confirmed idle (Max Avg CPU < {EC2_IDLE_PERCENT}%). Marked VIOLATION.")
        return True
    else:
        return False


def check_rds_metrics(resource, cloudwatch):
    """Checks RDS for max connections against RDS_IDLE_CONNECTIONS."""
    resource_id = resource['resource_id']
    logger.info(f"Checking RDS metric for {resource_id}...")

    dimensions = [{'Name': 'DBInstanceIdentifier', 'Value': resource_id}]
    start_time, end_time, period_seconds = calculate_time_window(CHECK_PERIOD_UNIT, CHECK_PERIOD_VALUE)

    datapoints = get_metric_statistics(
        client=cloudwatch,
        namespace='AWS/RDS',
        metric_name='DatabaseConnections',
        dimensions=dimensions,
        start_time=start_time,
        end_time=end_time,
        period=period_seconds,
        statistics=['Maximum'] # Check the Maximum connections in a period
    )

    is_idle = True
    if not datapoints:
        logger.warning(f"No RDS Connection data found for {resource_id}. Cannot confirm idleness.")
        return False

    for dp in datapoints:
        max_connections = dp.get('Maximum', 1) 
        if max_connections > RDS_IDLE_CONNECTIONS:
            logger.info(f"RDS {resource_id} showed usage (Max {max_connections} connections). Marked compliant.")
            is_idle = False
            break

    if is_idle:
        resource['reason'] += f" | Metric: Max Connections = {int(RDS_IDLE_CONNECTIONS)} for {CHECK_PERIOD_VALUE} {CHECK_PERIOD_UNIT}"
        resource['is_metric_violation'] = True
        logger.info(f"🔴 RDS {resource_id} confirmed idle (Max Connections <= {int(RDS_IDLE_CONNECTIONS)}). Marked VIOLATION.")
        return True
    else:
        return False


def lambda_handler(event, context):
    violations_from_discovery = event.get('violations', [])
    execution_id = event.get('execution_id')
    final_violations = []

    logger.info(f"Starting Metric Check for {len(violations_from_discovery)} discovered resources. Window: {CHECK_PERIOD_VALUE} {CHECK_PERIOD_UNIT}")

    for resource in violations_from_discovery:
        # Only process resources flagged by Discovery as needing a metric check
        if resource.get('needs_metric_check') is True:
            resource_type = resource.get('resource_type')
            region = resource.get('region')

            if not region or region == 'global':
                 logger.warning(f"Skipping metric check for {resource.get('resource_id')} due to invalid region: {region}")
                 resource['reason'] += " | Metric Check Skipped (Invalid Region)"
                 final_violations.append(resource)
                 continue

            try:
                cloudwatch_client = boto3.client('cloudwatch', region_name=region)
            except Exception as e:
                logger.error(f"❌ Failed to create CloudWatch client for {region}: {e}")
                resource['reason'] += " | CloudWatch client failed to initialize"
                final_violations.append(resource)
                continue

            metric_violation_confirmed = False

            if resource_type == 'EC2':
                metric_violation_confirmed = check_ec2_metrics(resource, cloudwatch_client)
            elif resource_type == 'RDS':
                metric_violation_confirmed = check_rds_metrics(resource, cloudwatch_client)

            if metric_violation_confirmed:
                final_violations.append(resource) 
            else:
                 logger.info(f"Resource {resource.get('resource_id')} ({resource_type}) in {region} passed the metric check (compliant or insufficient data).")

        else:
            # Append non-metric violations (S3, IAM, EIP, Tag-only EC2) directly to the final list
            final_violations.append(resource)

    logger.info(f"✅ Metric Check complete. Passing {len(final_violations)} confirmed violations to CheckStatus.")

    return {'execution_id': execution_id, 'violations': final_violations}