## Automatically update AWS resources with AWS IP Ranges

This project creates Lambda function that automatically add required AWS Identity and Access Management (IAM) policies to current Amazon Elastic Compute Cloud (Amazon EC2) instance profiles or associate a profile to EC2 instances without a profile associated.  
You can use it as a Lambda function scheduled at a recurrent time using EventBridge Rule or manually running the python code when required.

It is a best practice to manage your EC2 instances using AWS Systems Manager Session Manager and get EC2 instance's memory usage metric via CloudWatch Agent.  
In order to allow SSM Agent and CloudWatch Agent to communicate with their respective endpoint, EC2 instance needs to have some permissions.


## Overview

The CloudFormation template `cloudformation/template.yml` creates a stack with the following resources:

1. AWS Lambda function. The function's code is in `lambda/add_policy_to_ec2_instance.py` and is written in Python compatible with version 3.10.
1. Lambda function's execution role.
1. Event Bridge role to execute Lambda at a regular time.

```
                          +-----------------+
                          | Lambda          |
                          | Execution Role  |
                          +--------+--------+
                                   |
                                   |
+--------------------+    +--------+--------+      +-------------------+
|Event Bridge Rule   +--->+ Lambda function +------>+IAM Role          |
+--------------------+    +--------+--------+      +-------------------+
                                   |
                                   v
                          +--------+--------+
                          | CloudWatch Logs |
                          +-----------------+
```

> **NOTE ABOUT REGIONS DEPLOY**  
> There is no reason to deploy this solution twice inside the same region.  
> If you have a reason for doing it, please open an issue and let's talk about it.
> IAM Roles are global, but EC2 instances where roles are associated are regional, so you need to deploy this solution on each region where you want to ensure EC2 instances will have the correct policies attached on it.


## Lambda configuration

By default, Lambda will add the following policies to any role that is associated with an EC2 instance. If policie is already attached to the role, it will do nothing.

If you need to add more policies, change the list associated with variable `POLICIES_TO_ADD`.

```python
POLICIES_TO_ADD = [
    'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy',
    'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    ]
```

> **NOTE**  
> It doesn't work with in-line policies!


You can also set Lambda environment variable called `INSTANCE_PROFILE_NAME` with the name of the IAM instance profile to associate with EC2 instance. It will only associate this instance profile if the instance doesn't have any profile associated yet.

Also, if this environment variable is empty or not found, it will do nothing!


## Setup

These are the overall steps to deploy:

**Setup using CloudFormation**
1. Validate CloudFormation template file.
1. Create the CloudFormation stack.
1. Package the Lambda code into a `.zip` file.
1. Update Lambda function with the packaged code.

**Setup using Terraform**
1. Initialize Terraform state
1. Validate Terraform template.
1. Apply Terraform template.

**After setup**
1. Trigger a test Lambda invocation.
1. Clean-up





## Setup using CloudFormation
To simplify setup and deployment, assign the values to the following variables. Replace the values according to your deployment options.

```bash
export AWS_REGION="sa-east-1"
export CFN_STACK_NAME="add-policy-to-ec2-instance"
```

> **IMPORTANT:** Please, use AWS CLI v2

### 1. Validate CloudFormation template

Ensure the CloudFormation template is valid before use it.

```bash
aws cloudformation validate-template --template-body file://cloudformation/template.yml
```

### 2. Create CloudFormation stack

At this point it will create Lambda function with a dummy code.  
You will update it later.

```bash
aws cloudformation create-stack --stack-name "${CFN_STACK_NAME}" \
  --capabilities CAPABILITY_IAM \
  --template-body file://cloudformation/template.yml && {
    ### Wait for stack to be created
    aws cloudformation wait stack-create-complete --stack-name "${CFN_STACK_NAME}"
}
```

If the stack creation fails, troubleshoot by reviewing the stack events. The typical failure reasons are insufficient IAM permissions.

### 3. Create the packaged code

```bash
zip --junk-paths lambda.zip lambda/add_policy_to_ec2_instance.py
```

### 4. Update lambda package code

```bash
FUNCTION_NAME=$(aws cloudformation describe-stack-resources --stack-name "${CFN_STACK_NAME}" --query "StackResources[?LogicalResourceId=='LambdaFunction'].PhysicalResourceId" --output text)
aws lambda update-function-code --function-name "${FUNCTION_NAME}" --zip-file fileb://lambda.zip --publish
```






## Setup using Terraform

Terraform template uses the following providers:
* aws
* archive

> **IMPORTANT:** Please, use Terraform version 1.3.7 or higher

### 1. Initialize Terraform state
```bash
cd terraform/
terraform init
```

### 2. Validate Terraform template

Ensure Terraform template is valid before use it.

```bash
terraform validate
```

### 3. Apply Terraform template

```bash
terraform apply
```



## After setup

### 1a. Trigger a test Lambda invocation with the AWS CLI

After the stack is created, AWS resources are not updated until the schedule time. To test the function and update AWS resources with the policies defined for the first time, do a test invocation with the AWS CLI command below:

**CloudFormation**
```bash
aws lambda invoke --function-name "${FUNCTION_NAME}" lambda_return.json
```

**Terraform**
```bash
FUNCTION_NAME=$(terraform output | grep 'lambda_name' | cut -d ' ' -f 3 | tr -d '"')
aws lambda invoke --function-name "${FUNCTION_NAME}" lambda_return.json
```

After successful invocation, you should receive the response below with no errors.

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

The content of the `lambda_return.json` will list all AWS resources created or updated by the Lambda function with IP ranges from configured services.

### 1b. Trigger a test Lambda invocation with the AWS Console

Alternatively, you can invoke the test event in the AWS Lambda console with sample event below.

```json
{ }
```

### 2. Clean-up

Remove the temporary files, remove CloudFormation stack and destroy Terraform resources.

**CloudFormation**  
```bash
rm lambda.zip
rm lambda_return.json
aws cloudformation delete-stack --stack-name "${CFN_STACK_NAME}"
unset AWS_REGION
unset CFN_STACK_NAME
```

**Terraform**  
```bash
rm lambda_return.json
terraform destroy
```


> **ATTENTION**  
> When you remove CloudFormation stack, or destroy Terraform resources, it will NOT remove policies from the roles updated by this solution.  
> If you want to remove it, you need to do it manually.


## Lambda function customization

After the stack is created, you can customize the Lambda function's execution log level by editing the function's [environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html).

* `LOG_LEVEL`: **Optional**. Set log level to increase or reduce verbosity. The default value is `INFO`. Possible values are:
  * CRITICAL
  * ERROR
  * WARNING
  * INFO
  * DEBUG


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
