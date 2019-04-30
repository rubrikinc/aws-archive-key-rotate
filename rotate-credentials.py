import rubrik_cdm
import boto3
import ast
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####user defined vaiables#####
#region containing secrets manager entries for rubrik clusters
secret_region = 'us-west-1'
#prefix used to identify appropriate secrets in scope
secret_prefix = '/rubrik/archive/'
#name of the iam user used for rubrik archive connectivity
iam_username = 'gurling-archive-test-user'

#connect to secrets manager and iam
secrets_client = boto3.client('secretsmanager', region_name=secret_region)
iam_client = boto3.client('iam')

#function to get dict of access keys for iam_username, oldest key is marked as depricated, newest key is marked as current
def get_current_access_keys(iam_client, iam_username):
    current_access_keys = {'depricated_access_key': None, 'current_access_key': None}
    access_keys = iam_client.list_access_keys(UserName=iam_username)['AccessKeyMetadata']
    if len(access_keys) == 0:
        current_access_keys['current_access_key'] = None
        current_access_keys['depricated_access_key'] = None
        print('get_current_access_keys - no access keys found for user \'{}\''.format(iam_username))     
    elif len(access_keys) == 1:
        current_access_keys['current_access_key'] = access_keys[0]
        current_access_keys['depricated_access_key'] = None
        print('get_current_access_keys - found current access key \'{}\' for user \'{}\''.format(current_access_keys['current_access_key']['AccessKeyId'], iam_username))
    else:
        key_dates = [access_key['CreateDate'] for access_key in access_keys]
        for access_key in access_keys:
            if access_key['CreateDate'] == max(key_dates):
                current_access_keys['current_access_key'] = access_key
                print('get_current_access_keys - found current access key \'{}\' for user \'{}\''.format(current_access_keys['current_access_key']['AccessKeyId'], iam_username))
            elif access_key['CreateDate'] == min(key_dates):
                current_access_keys['depricated_access_key'] = access_key
                print('get_current_access_keys - found depricated access key \'{}\' for user \'{}\''.format(current_access_keys['depricated_access_key']['AccessKeyId'], iam_username))
    return current_access_keys

#function to get a list of secrets from secret_region that match secret_prefix
def get_secrets_in_scope(secrets_client, secret_prefix):
    secrets_in_scope = []
    secrets = secrets_client.list_secrets()['SecretList']
    print('get_secrets_in_scope - found {} secrets in region \'{}\''.format(len(secrets), secret_region))
    for secret in secrets:
        if secret_prefix in secret['Name']:
            secrets_in_scope.append(secret)
            print('get_secrets_in_scope - secret {} is in scope for rotation'.format(secret['Name']))
    print('get_secrets_in_scope - found {} secrets in scope for rotation'.format(len(secrets_in_scope)))
    return secrets_in_scope

#function to get identify archives on specified rubrik cluster with name matching rubrik_archive name from secrets manager secret and access
#key that matches current_access_key's AccessKeyId
def get_archive_in_scope(rubrik, rubrik_cred, current_access_key):
    archive_in_scope = None
    archives = rubrik.get('internal', '/archive/object_store')['data']
    print('get_archive_in_scope - found {} archives on cluster \'{}\''.format(len(archives), rubrik_cred['rubrik_ip']))
    for archive in archives:
        if archive['definition']['name'] == rubrik_cred['rubrik_archive'] and archive['definition']['accessKey'] == current_access_key['AccessKeyId']:
            archive_in_scope = archive
            print('get_archive_in_scope - found matching archive \'{}\' with access key \'{}\' on cluster \'{}\''.format(archive['definition']['name'], archive['definition']['accessKey'], rubrik_cred['rubrik_ip']))
    if archive_in_scope is not None:
        return archive_in_scope
    else:
        print('get_archive_in_scope - no matching archives with name \'{}\' and access key \'{}\' found on cluster \'{}\':'.format(archive['definition']['name'], archive['definition']['accessKey'], rubrik_cred['rubrik_ip']))
        return None

#function to delete depricated access key from iam user with username matching iam_username
def delete_depricated_access_key(iam_client, depricated_access_key):
    print('delete_depricated_access_key - deleting depricated access key \'{}\''.format(depricated_access_key['AccessKeyId']))
    return iam_client.delete_access_key(UserName=iam_username, AccessKeyId=depricated_access_key['AccessKeyId'])

#function to create new access key for iam user with username matching iam_username
def create_new_access_key(iam_client, iam_username):
    new_access_key = iam_client.create_access_key(UserName=iam_username)['AccessKey']
    print('create_new_access_key - created new access key \'{}\''.format(new_access_key['AccessKeyId']))
    return new_access_key

#function to rotate access key on for matching archive on rubrik cluster specified in secret
def rotate_access_key(secret, iam_client, iam_username):
    #connect to the rubrik cluster for this secret    
    rubrik_cred = ast.literal_eval(secrets_client.get_secret_value(SecretId=secret['ARN'])['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_cred['rubrik_ip'], rubrik_cred['rubrik_user'], rubrik_cred['rubrik_password'])
    #find the archive that matches our secret
    global current_access_key
    archive = get_archive_in_scope(rubrik, rubrik_cred, current_access_key)
    #tidy up the depricated access key if we have an archive match and an existing depricated key
    global depricated_access_key
    if depricated_access_key is not None and archive is not None:
        print('rotate_access_key - found matching archive and depricated access key, deleting depricated access key')
        delete_depricated_access_key(iam_client, depricated_access_key)
        depricated_access_key = None
    elif depricated_access_key is not None and archive is None:
        print('rotate_access_key - found depricated access key but no matching archive on cluster \'{}\', skipping deletion of depricated access key'.format(rubrik_cred['rubrik_ip']))
    #check to see if we already have a new access key from this run, if not, create one            
    global new_access_key
    if new_access_key is None and archive is not None:
        print('rotate_access_key - found matching archive and no new access key, creating new access key')
        new_access_key = create_new_access_key(iam_client, iam_username)
        print('rotate_access_key - sleeping for 15 seconds to allow for access key propegation')
        time.sleep(15)
    elif new_access_key is not None and archive is not None:
        print('rotate_access_key - found matching archive and existing new access key, skipping access key creation')
    #update the iam credentials used for the matching achive
    if new_access_key is not None and archive is not None:
        print('rotate_access_key - updating archive \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        update_response = rubrik.update_aws_s3_cloudout(archive['definition']['name'], aws_access_key=new_access_key['AccessKeyId'], aws_secret_key=new_access_key['SecretAccessKey'])
        if update_response['definition']['accessKey'] == new_access_key['AccessKeyId']:
            print ('rotate_access_key - access key update success for \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        elif update_response['definition']['accessKey'] != new_access_key['AccessKeyId']:
            print('rotate_access_key - access key update failed for \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        return update_response
    else:
        return None

#initate automated secrets rotation
def rotate_secrets():
    #get current and depricated access keys for iam_user
    global current_access_key
    global depricated_access_key
    global new_access_key
    access_keys = get_current_access_keys(iam_client, iam_username)
    current_access_key = access_keys['current_access_key']
    depricated_access_key = access_keys['depricated_access_key']
    #init new_access_key global as None
    new_access_key = None
    #get list of clusters and archives in scope for archive credential rotation from secrets manager
    secrets_in_scope = get_secrets_in_scope(secrets_client, secret_prefix)
    #rotate the access key for each cluster and archive in scope, print the api response from rubrik
    for secret in secrets_in_scope:
        print('beginning credential rotation for secret \'{}\''.format(secret['Name']))
        response = rotate_access_key(secret, iam_client, iam_username)
        if response:
            print('successfully rotated credentials for secret \'{}\', response from rubrik:'.format(secret['Name']))
            print(response)
        else:
            print('no archive matching secret \'{}\''.format(secret['Name']))