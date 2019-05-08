# Quick Start Guide: Rubrik Bolt Instance - Custom Tags

## Introduction to Rubrik Bolt Instance - Custom Tags

Many Rubrik customers use cost allocation tags in order to assign cost centers to various assets runninng in their AWS accounts. In order to accomodate such cost allocation methods, the following solution has been created in order to allow for the assignment of custom tags to Rubrik's ephemeral EC2 instnaces.

## Components
The solution consists of the following components:
* An IAM Role, used to execute the lambda function
* An IAM Policy, used to provide the necessary permissions to the IAM Role
* A Lambda function, used to apply custom tags to the Rubrik Bolt instance
* A Cloudwatch event rule, used to trigger the Lambda function when a Rubrik Bolt instance is proision

## Installation
1) Create an IAM policy using [role_policy.json](./role_policy.json) as the policy document
2) Create an IAM role
    * select Lambda as the trusted entity
    * select the policy create with [role_policy.json](./role_policy.json) as the permissions policy
3) Create Lambda function
    * name the function as desired
    * set the runtime to Pythin 3.7
    * choose `Use existing role` and select your newly created role 
    * click create function
    * in your newly created function, paste the contents of lambda_function.py and click save
4) Create CloudWatch Events Rule
    * Click Create role in the Cloudwatch Events console
    * Paste the contents of rk_bolt_run_event.json into the Cloudwatch Event pattern
    * Select your newly created Lambda function as the target
    * Click configure details, name and describe your rule as desired, and click create rule
5) Edit the `custom_tags` variable in your lambda function to specify which tags should be applied to any bolt insntances that are provisioned