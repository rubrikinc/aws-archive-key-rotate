import rubrik_cdm
import boto3
import ast
import urllib3
import datetime
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####user defined vaiables#####
#region containing secrets manager entries for rubrik clusters
secret_region = 'us-west-1'
#prefix used to identify appropriate secrets in scope
secret_prefix = '/rubrik/archive/'
#name of the iam user used for rubrik archive connectivity
iam_username = 'gurling-archive-test-user'
#cloudwatch log stream for logging
log_group_name = '/rubrik/archive/rotate'
date = datetime.datetime.now()
log_stream_name = '{}/{}/{}/rotate_log'.format(date.strftime("%Y"), date.strftime("%m"), date.strftime("%d"))
#connect to secrets manager and iam
secrets_client = boto3.client('secretsmanager', region_name=secret_region)
iam_client = boto3.client('iam')
logs = boto3.client('logs', region_name=secret_region)

def init_cloudwatch(log_group_name, log_stream_name):
    log_group = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    if len(log_group['logGroups']) == 0:
        logs.create_log_group(logGroupName=log_group_name)
        log_group = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    log_stream = logs.describe_log_streams(logGroupName=log_group_name, logStreamNamePrefix=log_stream_name)
    if len(log_stream['logStreams']) == 0:
        logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        log_stream = logs.describe_log_streams(logGroupName=log_group_name, logStreamNamePrefix=log_stream_name)
    try:
        next_sequence_token = log_stream['logStreams'][0]['uploadSequenceToken']
    except KeyError:
        next_sequence_token = None
    return next_sequence_token

def log_cloudwatch(message):
    timestamp = int(round(time.time() * 1000))
    if sequence_token is None:
        response = logs.put_log_events(logGroupName=log_group_name, logStreamName=log_stream_name, logEvents=[{'timestamp': timestamp, 'message': message}])
        sequence_token = response['nextSequenceToken']
    else:
        response = logs.put_log_events(logGroupName=log_group_name, logStreamName=log_stream_name, logEvents=[{'timestamp': timestamp, 'message': message}], sequenceToken=sequence_token)
        sequence_token = response['nextSequenceToken']
    return response

#function to get dict of access keys for iam_username, oldest key is marked as depricated, newest key is marked as current
def get_current_access_keys(iam_client, iam_username):
    current_access_keys = {'depricated_access_key': None, 'current_access_key': None}
    access_keys = iam_client.list_access_keys(UserName=iam_username)['AccessKeyMetadata']
    if len(access_keys) == 0:
        current_access_keys['current_access_key'] = None
        current_access_keys['depricated_access_key'] = None
        log_cloudwatch('get_current_access_keys - no access keys found for user \'{}\''.format(iam_username))     
    elif len(access_keys) == 1:
        current_access_keys['current_access_key'] = access_keys[0]
        current_access_keys['depricated_access_key'] = None
        log_cloudwatch('get_current_access_keys - found current access key \'{}\' for user \'{}\''.format(current_access_keys['current_access_key']['AccessKeyId'], iam_username))
    else:
        key_dates = [access_key['CreateDate'] for access_key in access_keys]
        for access_key in access_keys:
            if access_key['CreateDate'] == max(key_dates):
                current_access_keys['current_access_key'] = access_key
                log_cloudwatch('get_current_access_keys - found current access key \'{}\' for user \'{}\''.format(current_access_keys['current_access_key']['AccessKeyId'], iam_username))
            elif access_key['CreateDate'] == min(key_dates):
                current_access_keys['depricated_access_key'] = access_key
                log_cloudwatch('get_current_access_keys - found depricated access key \'{}\' for user \'{}\''.format(current_access_keys['depricated_access_key']['AccessKeyId'], iam_username))
    return current_access_keys

#function to get a list of secrets from secret_region that match secret_prefix
def get_secrets_in_scope(secrets_client, secret_prefix):
    secrets_in_scope = []
    secrets = secrets_client.list_secrets()['SecretList']
    log_cloudwatch('get_secrets_in_scope - found {} secrets in region \'{}\''.format(len(secrets), secret_region))
    for secret in secrets:
        if secret_prefix in secret['Name']:
            secrets_in_scope.append(secret)
            log_cloudwatch('get_secrets_in_scope - secret {} is in scope for rotation'.format(secret['Name']))
    log_cloudwatch('get_secrets_in_scope - found {} secrets in scope for rotation'.format(len(secrets_in_scope)))
    return secrets_in_scope

#function to get identify archives on specified rubrik cluster with name matching rubrik_archive name from secrets manager secret and access
#key that matches current_access_key's AccessKeyId
def get_archive_in_scope(rubrik, rubrik_cred, current_access_key):
    archive_in_scope = None
    archives = rubrik.get('internal', '/archive/object_store')['data']
    log_cloudwatch('get_archive_in_scope - found {} archives on cluster \'{}\''.format(len(archives), rubrik_cred['rubrik_ip']))
    for archive in archives:
        if archive['definition']['name'] == rubrik_cred['rubrik_archive'] and archive['definition']['accessKey'] == current_access_key['AccessKeyId']:
            archive_in_scope = archive
            log_cloudwatch('get_archive_in_scope - found matching archive \'{}\' with access key \'{}\' on cluster \'{}\''.format(archive['definition']['name'], archive['definition']['accessKey'], rubrik_cred['rubrik_ip']))
    if archive_in_scope is not None:
        return archive_in_scope
    else:
        log_cloudwatch('get_archive_in_scope - no matching archives with name \'{}\' and access key \'{}\' found on cluster \'{}\':'.format(archive['definition']['name'], archive['definition']['accessKey'], rubrik_cred['rubrik_ip']))
        return None

#function to delete depricated access key from iam user with username matching iam_username
def delete_depricated_access_key(iam_client, depricated_access_key):
    log_cloudwatch('delete_depricated_access_key - deleting depricated access key \'{}\''.format(depricated_access_key['AccessKeyId']))
    return iam_client.delete_access_key(UserName=iam_username, AccessKeyId=depricated_access_key['AccessKeyId'])

#function to create new access key for iam user with username matching iam_username
def create_new_access_key(iam_client, iam_username):
    new_access_key = iam_client.create_access_key(UserName=iam_username)['AccessKey']
    log_cloudwatch('create_new_access_key - created new access key \'{}\''.format(new_access_key['AccessKeyId']))
    return new_access_key

#function to rotate access key on for matching archive on rubrik cluster specified in secret
def rotate_access_key(secret, iam_client, iam_username, access_keys):
    #connect to the rubrik cluster for this secret    
    rubrik_cred = ast.literal_eval(secrets_client.get_secret_value(SecretId=secret['ARN'])['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_cred['rubrik_ip'], rubrik_cred['rubrik_user'], rubrik_cred['rubrik_password'])
    #find the archive that matches our secret
    archive = get_archive_in_scope(rubrik, rubrik_cred, access_keys['current_access_key'])
    #tidy up the depricated access key if we have an archive match and an existing depricated key
    if access_keys['depricated_access_key'] is not None and archive is not None:
        log_cloudwatch('rotate_access_key - found matching archive and depricated access key, deleting depricated access key')
        delete_depricated_access_key(iam_client, access_keys['depricated_access_key'])
        access_keys['depricated_access_key'] = None
    elif access_keys['depricated_access_key'] is not None and archive is None:
        log_cloudwatch('rotate_access_key - found depricated access key but no matching archive on cluster \'{}\', skipping deletion of depricated access key'.format(rubrik_cred['rubrik_ip']))
    #check to see if we already have a new access key from this run, if not, create one            
    global new_access_key
    if new_access_key is None and archive is not None:
        log_cloudwatch('rotate_access_key - found matching archive and no new access key, creating new access key')
        new_access_key = create_new_access_key(iam_client, iam_username)
        log_cloudwatch('rotate_access_key - sleeping for 15 seconds to allow for access key propegation')
        time.sleep(15)
    elif new_access_key is not None and archive is not None:
        log_cloudwatch('rotate_access_key - found matching archive and existing new access key, skipping access key creation')
    #update the iam credentials used for the matching achive
    if new_access_key is not None and archive is not None:
        log_cloudwatch('rotate_access_key - updating archive \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        update_response = rubrik.update_aws_s3_cloudout(archive['definition']['name'], aws_access_key=new_access_key['AccessKeyId'], aws_secret_key=new_access_key['SecretAccessKey'])
        if update_response['definition']['accessKey'] == new_access_key['AccessKeyId']:
            log_cloudwatch ('rotate_access_key - access key update success for \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        elif update_response['definition']['accessKey'] != new_access_key['AccessKeyId']:
            log_cloudwatch('rotate_access_key - access key update failed for \'{}\' on \'{}\''.format(archive['definition']['name'], rubrik_cred['rubrik_ip']))
        return update_response
    else:
        return None

#initate automated secrets rotation
def rotate_secrets():
    #logging init
    sequence_token = init_cloudwatch(log_group_name, log_stream_name)
    #get current and depricated access keys for iam_user
    access_keys = get_current_access_keys(iam_client, iam_username)
    #init new_access_key global as None
    global new_access_key
    new_access_key = None
    #get list of clusters and archives in scope for archive credential rotation from secrets manager
    secrets_in_scope = get_secrets_in_scope(secrets_client, secret_prefix)
    #rotate the access key for each cluster and archive in scope, log_cloudwatch the api response from rubrik
    for secret in secrets_in_scope:
        log_cloudwatch('rotate_secrets - beginning credential rotation for secret \'{}\''.format(secret['Name']))
        response = rotate_access_key(secret, iam_client, iam_username, access_keys)
        if response:
            log_cloudwatch('rotate_secrets - successfully rotated credentials for secret \'{}\', response from rubrik:'.format(secret['Name']))
            log_cloudwatch(response)
        else:
            log_cloudwatch('rotate_secrets - no archive matching secret \'{}\''.format(secret['Name']))

rotate_secrets()
