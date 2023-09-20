terraform {
  required_providers {
    aws = {
      version = "~> 5.6.2"
    }
    archive = {
      version = ">= 2.4.0"
    }
  }

  required_version = "~> 1.5.2"
}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "add_policy_to_ec2_instance" {
  name_prefix = "AddPolicyToEC2Instance"
  description = "Managed by update Add Policy To EC2 Instance Lambda"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {
            "Service" : "lambda.amazonaws.com"
          },
          "Action" : "sts:AssumeRole"
        }
      ]
    }
  )

  inline_policy {
    name = "IAM"

    # You can also specify the ARN of an AWS managed policy in a policy's Condition element.
    # The ARN of an AWS managed policy uses the special alias "aws" in the policy ARN instead of an account ID, as in this example:
    # "Condition": {"ArnEquals": 
    #   {"iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"}
    # }
    # Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html#access_controlling-resources
    policy = jsonencode(
      {
        "Version" : "2012-10-17",
        "Statement" : [
          {
            "Effect" : "Allow",
            "Action" : "iam:AttachRolePolicy",
            "Resource" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*",
            "Condition" : {
              "ArnEquals" : {
                "iam:PolicyARN" : [
                  "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
                  "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                ]
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : "iam:GetInstanceProfile",
            "Resource" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:instance-profile/*"

          },
          {
            "Effect" : "Allow",
            "Action" : "iam:ListAttachedRolePolicies",
            "Resource" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*"
          }
        ]
      }
    )
  }

  inline_policy {
    name = "EC2"

    policy = jsonencode(
      {
        "Version" : "2012-10-17",
        "Statement" : [
          {
            "Effect" : "Allow",
            "Action" : "ec2:DescribeInstances",
            "Resource" : "*",
            "Condition" : {
              "StringEquals" : {
                "ec2:Region" : "${data.aws_region.current.name}"
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : "ec2:AssociateIamInstanceProfile",
            "Resource" : "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*",
            "Condition" : {
              "StringEquals" : {
                "ec2:Region" : "${data.aws_region.current.name}"
              }
            }
          },
          {
            "Effect" : "Allow",
            "Action" : "iam:PassRole",
            "Resource" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/*",
            "Condition" : {
              "StringEquals" : {
                "iam:PassedToService" : "ec2.amazonaws.com"
              },
              "ArnLike" : {
                "iam:AssociatedResourceARN" : [
                  "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
                ]
              }
            }
          }
        ]
      }
    )
  }

}

# Zip lambda source code.
data "archive_file" "lambda_source" {
  type = "zip"
  #source_dir  = var.src_path
  output_path = "/tmp/lambda.zip"

  source {
    filename = "add_policy_to_ec2_instance.py"
    content  = file("../lambda/add_policy_to_ec2_instance.py")
  }
}
resource "aws_lambda_function" "add_policy_to_ec2_instance" {
  # checkov:skip=CKV_AWS_50:X-ray tracing not required
  # checkov:skip=CKV_AWS_116:Code log errors on CloudWatch logs
  # checkov:skip=CKV_AWS_117:Not required to run inside a VPC
  # checkov:skip=CKV_AWS_173:Variable is not sensitive
  # checkov:skip=CKV_AWS_272:Code signer not required

  filename                       = data.archive_file.lambda_source.output_path
  source_code_hash               = filebase64sha256(data.archive_file.lambda_source.output_path)
  function_name                  = "AddPolicyToEC2Instance"
  description                    = "This Lambda function, invoked by an EventBridge rule, updates IAM role with policies specified"
  role                           = aws_iam_role.add_policy_to_ec2_instance.arn
  handler                        = "add_policy_to_ec2_instance.lambda_handler"
  runtime                        = "python3.11"
  timeout                        = 300
  reserved_concurrent_executions = 2
  memory_size                    = 256
  architectures                  = ["arm64"]

  environment {
    variables = {
      LOG_LEVEL             = "INFO"
      INSTANCE_PROFILE_NAME = ""
    }
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.add_policy_to_ec2_instance.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.add_policy_to_ec2_instance.arn
}


resource "aws_cloudwatch_event_rule" "add_policy_to_ec2_instance" {
  name_prefix         = "AddPolicyToEC2Instance"
  description         = "Run Lambda to add policies to EC2 instance"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "add_policy_to_ec2_instance" {
  arn  = aws_lambda_function.add_policy_to_ec2_instance.arn
  rule = aws_cloudwatch_event_rule.add_policy_to_ec2_instance.name
}



output "lambda_name" {
  value = aws_lambda_function.add_policy_to_ec2_instance.function_name
}