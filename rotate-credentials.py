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
new_access_key = None

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

def get_secrets_in_scope(secrets_client, secret_prefix):
    secrets_in_scope = []
    secrets = secrets_client.list_secrets()['SecretList']
    for secret in secrets:
        if secret_prefix in secret['Name']:
            secrets_in_scope.append(secret)
    return secrets_in_scope

def get_archive_in_scope(rubrik, rubrik_cred, current_access_key):
    archive_in_scope = None
    archives = rubrik.get('internal', '/archive/object_store')['data']
    for archive in archives:
        if archive['definition']['name'] == rubrik_cred['rubrik_archive'] and archive['definition']['accessKey'] == current_access_key['AccessKeyId']:
            archive_in_scope = archive
            print('found matching archive {} with access key {}'.format(archive['definition']['name'], archive['definition']['accessKey']))
    if archive_in_scope is not None:
        return archive_in_scope
    else:
        print('no matching archive found on {}:'.format(rubrik_cred['rubrik_ip']))
        return None

def delete_depricated_key(depricated_access_key):
    print('deleting depricated access key')
    iam_client.delete_access_key(UserName=iam_username, AccessKeyId=depricated_access_key['AccessKeyId'])

def create_new_access_key():
    new_access_key = iam_client.create_access_key(UserName=iam_username)['AccessKey']
    print('Created new access key:')
    print(new_access_key)
    return new_access_key

def rotate_access_key(secret):

    #connect to the Rubrik cluster for this secret    
    rubrik_cred = ast.literal_eval(secrets_client.get_secret_value(SecretId=secret['ARN'])['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_cred['rubrik_ip'], rubrik_cred['rubrik_user'], rubrik_cred['rubrik_password'])

    #find the archive that matches our secret
    archive = get_archive_in_scope(rubrik, rubrik_cred, current_access_key)

    #tidy up the depricated access key if we have an archive match and an existing depricated key
    global depricated_access_key

    if depricated_access_key is not None and archive is not None:
        delete_depricated_key(depricated_access_key)
        depricated_access_key = None

    #check to see if we already have a new access key from this run, if not, create one            
    global new_access_key
    if new_access_key is None and archive is not None:
        new_access_key = create_new_access_key()
            
    #update the IAM credentials used for the matching achive
    print('Updating archive on {}'.format(rubrik_cred['rubrik_ip']))
    update_response = rubrik.update_aws_s3_cloudout(archive['definition']['name'], aws_access_key=new_access_key['AccessKeyId'], aws_secret_key=new_access_key['SecretAccessKey'])

    if update_response['accessKey']['name'] == new_access_key['AccessKeyId']:
        print ('access key update success')
    elif update_response['accessKey']['name'] != new_access_key['AccessKeyId']:
        print('access key update failed')
    return update_response

#secrets_in_scope = get_secrets_in_scope(secrets_client, secret_prefix)

#for secret in secrets_in_scope:
    #rotate_access_key(secret)