"""
AWS Security Data Collector
Frequent security scanning for EC2, S3, and IAM
Author: Your Name
"""

import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    """
    Main Lambda function for security data collection
    """
    print("🚀 Starting Security Data Collection")
    
    try:
        # Initialize AWS clients
        ec2 = boto3.client('ec2')
        s3 = boto3.client('s3')
        iam = boto3.client('iam')
        
        security_findings = {
            'timestamp': datetime.utcnow().isoformat(),
            'ec2_findings': [],
            's3_findings': [],
            'iam_findings': []
        }
        
        # EC2 Security Scan
        scan_ec2_security(ec2, security_findings)
        
        # S3 Security Scan  
        scan_s3_security(s3, security_findings)
        
        # IAM Security Scan
        scan_iam_security(iam, security_findings)
        
        # Save results to S3
        save_to_s3(security_findings)
        
        print(f"✅ Security scan completed. Findings: {len(security_findings['ec2_findings'] + security_findings['s3_findings'] + security_findings['iam_findings'])}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security data collection successful',
                'findings_count': {
                    'ec2': len(security_findings['ec2_findings']),
                    's3': len(security_findings['s3_findings']),
                    'iam': len(security_findings['iam_findings'])
                }
            })
        }
        
    except Exception as e:
        print(f"❌ Security scan failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def scan_ec2_security(ec2_client, findings):
    """Scan EC2 instances for security issues"""
    try:
        instances = ec2_client.describe_instances()
        
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # Check for public instances
                if instance.get('PublicIpAddress'):
                    findings['ec2_findings'].append({
                        'type': 'PUBLIC_INSTANCE',
                        'risk': 'HIGH',
                        'instance_id': instance['InstanceId'],
                        'public_ip': instance['PublicIpAddress'],
                        'message': 'EC2 instance has public IP address'
                    })
                
    except Exception as e:
        print(f"⚠️ EC2 scan error: {e}")
        findings['ec2_findings'].append({
            'type': 'SCAN_ERROR',
            'risk': 'MEDIUM',
            'message': f'EC2 security scan failed: {str(e)}'
        })

def scan_s3_security(s3_client, findings):
    """Scan S3 buckets for security issues"""
    try:
        buckets = s3_client.list_buckets()
        
        for bucket in buckets['Buckets'][:20]:  # Limit to first 20 buckets
            try:
                # Check bucket ACL for public access
                acl = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                
                for grant in acl['Grants']:
                    if 'URI' in grant.get('Grantee', {}) and 'AllUsers' in grant['Grantee']['URI']:
                        findings['s3_findings'].append({
                            'type': 'PUBLIC_BUCKET',
                            'risk': 'HIGH',
                            'bucket_name': bucket['Name'],
                            'message': 'S3 bucket has public access'
                        })
                        break
                        
            except Exception as e:
                # Skip buckets we can't access
                continue
                
    except Exception as e:
        print(f"⚠️ S3 scan error: {e}")
        findings['s3_findings'].append({
            'type': 'SCAN_ERROR', 
            'risk': 'MEDIUM',
            'message': f'S3 security scan failed: {str(e)}'
        })

def scan_iam_security(iam_client, findings):
    """Scan IAM for security issues"""
    try:
        users = iam_client.list_users()
        
        for user in users['Users']:
            # Check MFA status
            mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                findings['iam_findings'].append({
                    'type': 'NO_MFA',
                    'risk': 'HIGH',
                    'user_name': user['UserName'],
                    'message': 'IAM user has no MFA device enabled'
                })
            
            # Check access key age
            access_keys = iam_client.list_access_keys(UserName=user['UserName'])
            for key in access_keys['AccessKeyMetadata']:
                key_age = (datetime.now(key['CreateDate'].replace(tzinfo=None)).days
                if key_age > 90:
                    findings['iam_findings'].append({
                        'type': 'OLD_ACCESS_KEY',
                        'risk': 'MEDIUM',
                        'user_name': user['UserName'],
                        'key_age_days': key_age,
                        'message': f'Access key is {key_age} days old'
                    })
                    
    except Exception as e:
        print(f"⚠️ IAM scan error: {e}")
        findings['iam_findings'].append({
            'type': 'SCAN_ERROR',
            'risk': 'MEDIUM', 
            'message': f'IAM security scan failed: {str(e)}'
        })

def save_to_s3(findings):
    """Save security findings to S3"""
    try:
        s3 = boto3.client('s3')
        
        s3.put_object(
            Bucket='security-command-center-data',
            Key=f"security-scans/{datetime.utcnow().strftime('%Y/%m/%d/%H-%M-scan.json')}",
            Body=json.dumps(findings, indent=2)
        )
        print("💾 Security findings saved to S3")
        
    except Exception as e:
        print(f"⚠️ Failed to save to S3: {e}")

# Local testing
if __name__ == "__main__":
    # Test the function locally
    test_event = {}
    test_context = type('obj', (object,), {})()
    
    result = lambda_handler(test_event, test_context)
    print(json.dumps(result, indent=2))
