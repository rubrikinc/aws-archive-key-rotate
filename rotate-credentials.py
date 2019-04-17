import rubrik_cdm
import boto3
import ast

region = 'us-west-1'
secret_prefix = '/rubrik/archive/'

client = boto3.client('secretsmanager', region_name=region)
secrets_in_scope = []

secrets = client.list_secrets()['SecretList']
for secret in secrets:
    if secret_prefix in secret['Name']:
        secrets_in_scope.append(secret)

for secret in secrets_in_scope:
    rubrik_cred = ast.literal_eval(client.get_secret_value(SecretId=secret['ARN'])['SecretString'])
    rubrik = rubrik_cdm.Connect(rubrik_cred['rubrik_ip'], rubrik_cred['rubrik_user'], rubrik_cred['rubrik_password'])
    for archive in rubrik.get('internal', '/archive/object_store'):
        if archive['data']['definition']['name'] == rubrik_cred['rubrik_archive']:
            #add code to update credentials on archive location

