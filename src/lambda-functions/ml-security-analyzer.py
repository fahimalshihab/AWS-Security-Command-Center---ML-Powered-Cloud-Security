"""
ML-Powered Security Analyzer
Advanced threat detection and email alerts
Author: Your Name
"""

import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    """
    Main Lambda function for ML security analysis
    """
    print("🤖 Starting ML Security Analysis")
    
    try:
        # Initialize AWS clients
        cloudwatch = boto3.client('cloudwatch')
        sns = boto3.client('sns')
        
        # Run comprehensive security audit
        security_scores = run_security_audit()
        
        # Send metrics to CloudWatch dashboard
        send_security_metrics(cloudwatch, security_scores)
        
        # Send email alerts
        send_security_email(sns, security_scores)
        
        print(f"✅ ML analysis complete. Security score: {security_scores['security_health']}/100")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'ML security analysis successful',
                'security_score': security_scores['security_health'],
                'active_threats': security_scores['active_threats']
            })
        }
        
    except Exception as e:
        print(f"❌ ML analysis failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def run_security_audit():
    """
    Comprehensive security audit with ML-inspired scoring
    """
    ec2 = boto3.client('ec2')
    s3 = boto3.client('s3') 
    iam = boto3.client('iam')
    
    audit_results = {
        'security_health': 100,  # Start with perfect score
        'active_threats': 0,
        'ec2_score': 100,
        's3_score': 100,
        'iam_score': 100,
        'findings': [],
        'scan_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    }
    
    # EC2 Security Assessment
    ec2_findings = audit_ec2_security(ec2)
    audit_results['findings'].extend(ec2_findings)
    audit_results['active_threats'] += len([f for f in ec2_findings if f['risk'] == 'HIGH'])
    audit_results['ec2_score'] = calculate_service_score(ec2_findings)
    
    # S3 Security Assessment
    s3_findings = audit_s3_security(s3)
    audit_results['findings'].extend(s3_findings)
    audit_results['active_threats'] += len([f for f in s3_findings if f['risk'] == 'HIGH'])
    audit_results['s3_score'] = calculate_service_score(s3_findings)
    
    # IAM Security Assessment  
    iam_findings = audit_iam_security(iam)
    audit_results['findings'].extend(iam_findings)
    audit_results['active_threats'] += len([f for f in iam_findings if f['risk'] == 'HIGH'])
    audit_results['iam_score'] = calculate_service_score(iam_findings)
    
    # Calculate overall security health
    audit_results['security_health'] = calculate_overall_score(audit_results)
    
    return audit_results

def audit_ec2_security(ec2_client):
    """Audit EC2 security with detailed findings"""
    findings = []
    
    try:
        # Get all running instances
        instances = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        public_instances = 0
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if instance.get('PublicIpAddress'):
                    public_instances += 1
                    findings.append({
                        'type': 'PUBLIC_EC2_INSTANCE',
                        'risk': 'HIGH',
                        'resource': instance['InstanceId'],
                        'details': 'Instance has public IP address exposed to internet',
                        'recommendation': 'Move to private subnet or implement strict security groups'
                    })
        
        print(f"🔍 EC2 Audit: {public_instances} public instances found")
        
    except Exception as e:
        findings.append({
            'type': 'EC2_AUDIT_FAILED',
            'risk': 'MEDIUM',
            'resource': 'EC2 Service',
            'details': f'EC2 security audit failed: {str(e)}',
            'recommendation': 'Check IAM permissions and network connectivity'
        })
    
    return findings

def audit_s3_security(s3_client):
    """Audit S3 security with detailed findings"""
    findings = []
    
    try:
        buckets = s3_client.list_buckets()
        public_buckets = 0
        
        for bucket in buckets['Buckets'][:15]:  # Check first 15 buckets
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                
                for grant in acl['Grants']:
                    if 'URI' in grant.get('Grantee', {}) and 'AllUsers' in grant['Grantee']['URI']:
                        public_buckets += 1
                        findings.append({
                            'type': 'PUBLIC_S3_BUCKET',
                            'risk': 'HIGH', 
                            'resource': bucket['Name'],
                            'details': 'Bucket has public read/write access',
                            'recommendation': 'Implement bucket policies to restrict public access'
                        })
                        break
            except:
                continue
        
        print(f"🔍 S3 Audit: {public_buckets} public buckets found")
        
    except Exception as e:
        findings.append({
            'type': 'S3_AUDIT_FAILED',
            'risk': 'MEDIUM',
            'resource': 'S3 Service',
            'details': f'S3 security audit failed: {str(e)}',
            'recommendation': 'Check IAM permissions for S3 access'
        })
    
    return findings

def audit_iam_security(iam_client):
    """Audit IAM security with detailed findings"""
    findings = []
    
    try:
        users = iam_client.list_users()
        users_without_mfa = 0
        
        for user in users['Users']:
            # Check MFA status
            mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                users_without_mfa += 1
                findings.append({
                    'type': 'USER_WITHOUT_MFA',
                    'risk': 'HIGH',
                    'resource': user['UserName'],
                    'details': 'User account has no Multi-Factor Authentication enabled',
                    'recommendation': 'Enable MFA device for user immediately'
                })
            
            # Check for access keys over 90 days old
            access_keys = iam_client.list_access_keys(UserName=user['UserName'])
            for key in access_keys['AccessKeyMetadata']:
                key_age = (datetime.now(key['CreateDate'].replace(tzinfo=None)).days
                if key_age > 90:
                    findings.append({
                        'type': 'OLD_ACCESS_KEY',
                        'risk': 'MEDIUM',
                        'resource': user['UserName'],
                        'details': f'Access key is {key_age} days old (should be rotated every 90 days)',
                        'recommendation': 'Rotate access key immediately'
                    })
        
        print(f"🔍 IAM Audit: {users_without_mfa} users without MFA found")
        
    except Exception as e:
        findings.append({
            'type': 'IAM_AUDIT_FAILED',
            'risk': 'MEDIUM',
            'resource': 'IAM Service', 
            'details': f'IAM security audit failed: {str(e)}',
            'recommendation': 'Check IAM permissions for user listing'
        })
    
    return findings

def calculate_service_score(findings):
    """Calculate security score for a service (0-100)"""
    if not findings:
        return 100
    
    high_risk = len([f for f in findings if f['risk'] == 'HIGH'])
    medium_risk = len([f for f in findings if f['risk'] == 'MEDIUM'])
    
    # Deduct points based on risk levels
    score = 100 - (high_risk * 30) - (medium_risk * 15)
    return max(0, score)

def calculate_overall_score(audit_results):
    """Calculate overall security health score"""
    # Weighted average of service scores
    weights = {'ec2_score': 0.3, 's3_score': 0.3, 'iam_score': 0.4}
    total_score = 0
    
    for service, weight in weights.items():
        total_score += audit_results[service] * weight
    
    return int(total_score)

def send_security_metrics(cloudwatch_client, scores):
    """Send security metrics to CloudWatch for dashboard"""
    try:
        cloudwatch_client.put_metric_data(
            Namespace='SecurityCommandCenter',
            MetricData=[
                {
                    'MetricName': 'SecurityHealthScore',
                    'Value': scores['security_health'],
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                },
                {
                    'MetricName': 'ActiveThreats',
                    'Value': scores['active_threats'],
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                },
                {
                    'MetricName': 'EC2SecurityScore',
                    'Value': scores['ec2_score'],
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                },
                {
                    'MetricName': 'S3SecurityScore',
                    'Value': scores['s3_score'],
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                },
                {
                    'MetricName': 'IAMSecurityScore',
                    'Value': scores['iam_score'],
                    'Unit': 'Count',
                    'Timestamp': datetime.utcnow()
                }
            ]
        )
        print("📊 Security metrics sent to CloudWatch")
        
    except Exception as e:
        print(f"⚠️ Failed to send CloudWatch metrics: {e}")

def send_security_email(sns_client, scores):
    """Send professional security alert email"""
    try:
        topic_arn = 'arn:aws:sns:ap-south-1:641550531422:security-alerts'
        
        # Determine alert level and subject
        if scores['security_health'] >= 80:
            status_emoji = "✅"
            subject = f"Security Scan: All Clear - Score {scores['security_health']}/100"
        elif scores['security_health'] >= 60:
            status_emoji = "⚠️"
            subject = f"Security Alert: Review Needed - Score {scores['security_health']}/100"
        else:
            status_emoji = "🚨"
            subject = f"CRITICAL: Security Issues - Score {scores['security_health']}/100"
        
        # Build email message
        email_message = f"""
{status_emoji} AWS SECURITY COMMAND CENTER - AUTOMATED SCAN REPORT

Scan Completed: {scores['scan_time']}

📊 SECURITY OVERVIEW:
• Overall Security Score: {scores['security_health']}/100
• Active Threats Identified: {scores['active_threats']}
• EC2 Security: {scores['ec2_score']}/100
• S3 Security: {scores['s3_score']}/100
• IAM Security: {scores['iam_score']}/100

"""
        
        if scores['findings']:
            email_message += "🔍 SECURITY FINDINGS:\n"
            for finding in scores['findings']:
                risk_icon = "🔴" if finding['risk'] == 'HIGH' else "🟡"
                email_message += f"\n{risk_icon} {finding['type']}\n"
                email_message += f"   Resource: {finding['resource']}\n"
                email_message += f"   Issue: {finding['details']}\n"
                email_message += f"   Action: {finding['recommendation']}\n"
        else:
            email_message += "🎉 EXCELLENT! No security issues detected.\n"
        
        email_message += f"""
⚠️ RECOMMENDED NEXT STEPS:
1. Review detailed findings in AWS Console
2. Address HIGH risk items within 24 hours
3. Implement recommended security improvements
4. Monitor dashboard for security trends

🔗 QUICK ACCESS:
• CloudWatch Dashboard: SecurityCommandCenter
• S3 Scan Results: security-command-center-data
• IAM Users Console: IAM > Users

---
This is an automated security scan from your AWS Security Command Center.
For questions, review the project documentation.
"""
        
        # Send email via SNS
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=email_message,
            Subject=subject
        )
        
        print(f"📧 Security alert email sent! Message ID: {response['MessageId']}")
        
    except Exception as e:
        print(f"❌ Failed to send security email: {e}")

# Local testing
if __name__ == "__main__":
    # Test the function locally
    test_event = {}
    test_context = type('obj', (object,), {})()
    
    result = lambda_handler(test_event, test_context)
    print(json.dumps(result, indent=2))
