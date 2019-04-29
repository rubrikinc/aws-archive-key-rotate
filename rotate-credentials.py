import rubrik_cdm
import boto3
import ast
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

secret_region = 'us-west-1'
secret_prefix = '/rubrik/archive/'
iam_username = 'gurling-archive-test-user'

secrets_client = boto3.client('secretsmanager', region_name=secret_region)
iam_client = boto3.client('iam')
access_keys = iam_client.list_access_keys(UserName=iam_username)['AccessKeyMetadata']
secrets_in_scope = []

#determine if we have 1 or two access keys and map their values appropriately
if len(access_keys)==2:
    if access_keys[1]['CreateDate'] > access_keys[0]['CreateDate']:
        current_access_key=access_keys[1]
        depricated_access_key=access_keys[0]
        print('Found two access keys')
        print('Depricated:')
        print(depricated_access_key)
        print('Current:')
        print(current_access_key)
    else:
        current_access_key=access_keys[0]
        depricated_access_key=access_keys[1]
        print('Found two access keys')
        print('Depricated:')
        print(depricated_access_key)
        print('Current:')
        print(current_access_key)
else:
    current_access_key=access_keys[0]
    depricated_access_key=None
    print('Found two access keys')
    print('Depricated:')
    print(depricated_access_key)
    print('Current:')
    print(current_access_key)

secrets = secrets_client.list_secrets()['SecretList']
for secret in secrets:
    if secret_prefix in secret['Name']:
        secrets_in_scope.append(secret)

#print('Secrets in scope:')
#print(secrets_in_scope)

for secret in secrets_in_scope:
    #connect to the Rubrik cluster for this secret    
    rubrik_cred = ast.literal_eval(secrets_client.get_secret_value(SecretId=secret['ARN'])['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_cred['rubrik_ip'], rubrik_cred['rubrik_user'], rubrik_cred['rubrik_password'])
    #find the archive that matches our secret
    for archive in rubrik.get('internal', '/archive/object_store')['data']:
        if archive['definition']['name'] == rubrik_cred['rubrik_archive'] and archive['definition']['accessKey'] == current_access_key['AccessKeyId']:
            print('found matching archive {} with access key {}'.format(archive['definition']['name'], archive['definition']['accessKey']))
            if depricated_access_key:
                print('deleting depricated access key')
                iam_client.delete_access_key(UserName=iam_username, AccessKeyId=depricated_access_key['AccessKeyId'])
                depricated_access_key = None
            new_access_key = iam_client.create_access_key(UserName=iam_username)['AccessKey']
            print('Created new access key:')
            print(new_access_key)
            time.sleep(5)
            #update the IAM credentials used for the matching achive
            print('Updating archive on {}'.format(rubrik_cred['rubrik_ip']))
            update_response = rubrik.update_aws_s3_cloudout(archive['definition']['name'], aws_access_key=new_access_key['AccessKeyId'], aws_secret_key=new_access_key['SecretAccessKey'])
            update_response = rubrik.update_aws_s3_cloudout(archive['definition']['name'], aws_access_key=new_access_key['AccessKeyId'], aws_secret_key=new_access_key['SecretAccessKey'])
            if depricated_access_key is not None and (update_response['accessKey']['name'] == new_access_key['AccessKeyId']):
                print ('access key update success, deleted depricated access key')
            elif depricated_access_key is not None and (update_response['accessKey']['name'] != new_access_key['AccessKeyId']):
                print('access key update failed, depricated access key')
            elif depricated_access_key is None and (update_response['accessKey']['name'] == new_access_key['AccessKeyId']):
                print('access key update success, no depricated access key')
            elif depricated_access_key is None and (update_response['accessKey']['name'] != new_access_key['AccessKeyId']):
                print('access key update failed, no depricated access key')
