# Quick Start Guide: AWS CloudOut Archive Credential Rotation

## Introduction to AWS CloudOut Archive Credential Rotation

Rubrik’s API first architecture enables organizations to embrace and integrate Rubrik functionality into their existing automation processes. Some Rubrik customers prefer to manage the rotation of secrets via the cron jobs. This solution is designed to allow customers to deploy a solution that provides IAM credential rotation for multiple Rubrik CloudOut archives to a single AWS account. The current version of this solution assumes the rotation logic will be executed via cron on an Amazon EC2 instance with an AWS IAM role assigned to it and connectivity to all Rubrik clusters in scope for rotation.

## Components
The solution consists of the following components:
* An IAM Role, assigned to the instance running the cron job
* An IAM Policy, used to provide the necessary permissions to the IAM Role
* A Python script, used to rotate the credentials of `IAMUSER` and update the relevant Rubrik CloudOut archives
* AWS Secrets Manager secrets, used to store the credentials for the Rubrik clusters with CloudOut archives requiring credential rotation

## Installation
1) Create an IAM policy using [role_policy.json](../role_policy.json) as the policy document. Be sure to update the following parameters from the sample policy prior to creating it:
    * replace all instances of `ACCOUNTNUMBER` with your AWS acount number
    * replace `REGION` with the region you will be using to store secrets in AWS Secrets Manager
    * replace `SECRETPREFIX` with the prefix you will be using to identify Rubrik CloudOut archive secrets (for example: /rubrik/archive/)
    * replace `IAMUSER` with the name of the AWS IAM user you are using for Rubrik CloudOut archiving
2) Create an IAM role
    * select EC2 as the trusted entity
    * select the policy created with [role_policy.json](../role_policy.json) as the permissions policy
    * assign this IAM role to the AWS instance that will be running the rotation cron job
3) Create AWS Secrets Manager secrets for each archive in scope
    * be sure each secret name begins with a string matching `SECRETPREFIX`
    * store the secret as `Other type of secret` an example format for these secrets is available in [secret_example.json](../secret_example.json)
    * rotation should be disabled since this iteration of the solution leverages cron for scheduling
4) Create and schedule the python script
    * place a copy of [rotate-credentials.py](../rotate-credentials.py) in the location you typically invoke cron scripts from (for example: /usr/bin/rotate-credentials.py) on the AWS instance that will be running the rotation cron job
    * update the following parameters in [rotate-credentials.py](../rotate-credentials.py) to your preferences and save the script:
        * set `secret_region` to the region you will be storing AWS Secrets Manager secrets in, this must match `REGION` above (example: secret_region = 'us-west-1')
        * set `secret_prefix` to the string you want to use to identify the secrets containing Rubrik credentials and archive names, this must match `SECRETPREFIX` above (example: secret_prefix = '/rubrik/archive/')
        * set `iam_username` to the name of the AWS IAM User that is performing CloudOut to your AWS account, this must match `IAMUSER` above (example: iam_username = 'gurling-archive-test-user')
        * update `log_group_name` and `log_stream_name` to your standards, if desired
    * run the script to test rotation via `python rotate-credentials.py`, here are some important things to be aware of before you proceed:
        * be sure to check the import statements at the top of `rotate-credentials.py` and verify that all dependencies are installed
            * currently, this solution requires you install the devel branch of the Rubrik Python SDK from as source described under `installation` [here](https://github.com/rubrikinc/rubrik-sdk-for-python/tree/devel)
        * the script will iterate through all secrets containing the prefix defined above and attempt rotation credential rotation for the CloudOut archive defined in each secret
        * if any secret name does not contain the specified prefix, the secret is ignored
        * all `rubrik_ip`'s defined in secrets must be accessible on port 443 from the Amazon EC2 instance running the cron job
        * `rubrik_user` and `rubrik_password` must correspond to a Rubrik user that has permission to update the IAM credentials used on `rubrik_archive` 
            * testing thus far has used the default admin user successfully 
        * in order for rotation to take place `rubrik_archive` must match the name of the CloudOut archive on the corresponding Rubrik cluster *exactly* **AND** the AWS IAM Access key ID used on the archive must match the *newest* Access key ID created for `IAMUSER`
            * if either does not match *exactly* the archive will be ignored and *other archives will be rotated*
            * mistakes may lead to expiring AWS IAM Access keys that are still in use on a CloudOut archive somewhere **please verify all secrets and archives before proceeding**
            * once rotation is in place, do not manually create new AWS IAM Access keys for `IAMUSER` without updating all CloudOut archives in scope to use them, rotation will begin to fail due to the fact that the the access key on the archive does not match the newest Access key for `IAMUSER`
    * once rotation is running successfully, schedule the script at your desired interval via cron
    
