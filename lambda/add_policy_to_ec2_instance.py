"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import logging
import os
from typing import Any

import boto3  # type: ignore

####

POLICIES_TO_ADD = [
    'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy',
    'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    ]

####### Get values from environment variables  ######

## Logging level options in less verbosity order. INFO is the default.
## If you enable DEBUG, it will log boto3 calls as well.
# CRITICAL
# ERROR
# WARNING
# INFO
# DEBUG

# Get logging level from environment variable
LOG_LEVEL = os.getenv('LOG_LEVEL', '').upper()
if LOG_LEVEL not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
    LOG_LEVEL = 'INFO'

# Set up logging. Set the level if the handler is already configured.
if len(logging.getLogger().handlers) > 0:
    logging.getLogger().setLevel(LOG_LEVEL)
else:
    logging.basicConfig(level=LOG_LEVEL)


INSTANCE_PROFILE_NAME = os.getenv('INSTANCE_PROFILE_NAME', '')

# Define client for services
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

def describe_instances(client: Any) -> dict[str, Any]:
    """Describe all instances"""

    logging.info('describe_instances start')
    logging.debug(f'Parameter client: {client}')

    current_instances: dict[str, Any] = {}

    # Get all Instances using paginator
    logging.info('Describing all instances')
    paginator = client.get_paginator("describe_instances")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        reservations = page['Reservations']
        for reservation in reservations:
            instances = reservation['Instances']
            for instance in instances:
                if instance['State']['Name'] in ["shutting-down", "terminated"]:
                    logging.info(f'INFO - Instance \"{instance["InstanceId"]}\" is terminated or shutting-down, will ignore it.')
                else:
                    current_instances[instance["InstanceId"]] = instance

    logging.debug(f'Function return: {current_instances}')
    logging.info('describe_instances end')
    return current_instances

def get_instance_profile(instances: dict[str, Any]) -> dict[str, list[str]]:
    """Get the instance profile for each instance"""
    logging.info('get_instance_profile start')
    logging.debug(f'Parameter instances: {instances}')

    instance_profile: dict[str, list[str]] = {}

    for _, instance in instances.items():
        if 'IamInstanceProfile' in instance:
            instance_profile_arn = instance['IamInstanceProfile']['Arn']
            instance_id = instance['InstanceId']
            if instance_profile_arn in instance_profile:
                instance_profile[instance_profile_arn].append(instance_id)
            else:
                instance_profile[instance_profile_arn] = [instance_id]

    logging.debug(f'Function return: {instance_profile}')
    logging.info('get_instance_profile end')
    return instance_profile

def get_roles_from_instance_profiles(client: Any, instance_profiles: dict[str, list[str]]) -> dict[str, Any]:
    """Get the roles from the instance profile"""
    logging.info('get_roles_from_instance_profiles start')
    logging.debug(f'Parameter instance_profiles: {instance_profiles}')

    # Get the list of profile names
    profile_names: dict[str, str] = {}
    for instance_profile_arn, instance_ids in instance_profiles.items():
        profile_name = instance_profile_arn.split('/')[1]
        profile_names[profile_name] = instance_profile_arn

    # Get the roles from the profile names
    roles: dict[str, str] = {}
    for role_name in profile_names.keys():
        logging.info(f'Getting Instance Profile {role_name}')
        response = client.get_instance_profile(InstanceProfileName=role_name)
        logging.info(f'Got Instance Profile {role_name}')
        logging.debug(f'Response: {response}')
        for role in response['InstanceProfile']['Roles']:
            role_name = role['RoleName']
            roles[role_name] = role

    logging.debug(f'Function return: {roles}')
    logging.info('get_roles_from_instance_profiles end')
    return roles

def get_role_managed_policies(client: Any, roles: dict[str, Any]) -> dict[str, list[Any]]:
    """Get the managed policies from the roles"""
    logging.info('get_role_managed_policies start')
    logging.debug(f'Parameter roles: {roles}')

    role_policies: dict[str, list[Any]] = {}
    # Get the list of role names
    for role_name, _ in roles.items():
        logging.info(f'Getting attached role policies {role_name}')
        # Example:
        # {
        #     "AttachedPolicies": [
        #         {
        #             "PolicyName": "CloudWatchAgentServerPolicy",
        #             "PolicyArn": "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
        #         },
        #         {
        #             "PolicyName": "AmazonSSMManagedInstanceCore",
        #             "PolicyArn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        #         }
        # }
        response = client.list_attached_role_policies(RoleName=role_name)
        logging.info(f'Got attached role policies {role_name}')
        logging.debug(f'Response: {response}')
        role_policies[role_name] = response['AttachedPolicies']

    logging.debug(f'Function return: {role_policies}')
    return role_policies

def get_instances_without_profile(instances: dict[str, Any]) -> list[str]:
    """Get instances without a configured instance profile"""
    logging.info('get_instances_without_profile start')
    logging.debug(f'Parameter instances: {instances}')

    instances_without_profile: list[str] = []

    for _, instance in instances.items():
        if 'IamInstanceProfile' not in instance:
            instance_id = instance['InstanceId']
            instances_without_profile.append(instance_id)

    logging.debug(f'Function return: {instances_without_profile}')
    logging.info('get_instances_without_profile end')
    return instances_without_profile

#======================================================================================================================
# Lambda entry point
#======================================================================================================================

def lambda_handler(event, context):
    """Lambda function handler"""
    logging.info('lambda_handler start')
    logging.debug(f'Parameter event: {event}')
    logging.debug(f'Parameter context: {context}')
    roles_updated: list[str] = []
    instances_updated: list[str] = []
    try:
        # Get all current EC2 instances
        instances = describe_instances(ec2_client)
        # Get current instance profile from instances
        instance_profiles = get_instance_profile(instances)
        # Get roles from instance profiles
        roles = get_roles_from_instance_profiles(iam_client, instance_profiles)
        # Get role managed policies
        role_policies = get_role_managed_policies(iam_client, roles)

        # Get the policies to add on role
        policies_to_add_on_role: dict[str, list[str]] = {}
        for role_name, policies in role_policies.items():
            policy_arns = { policy['PolicyArn']:policy['PolicyName'] for policy in policies }
            for policy_arn in POLICIES_TO_ADD:
                if policy_arn in policy_arns:
                    logging.info(f'Found policy: {policy_arn} into role: {role_name}')
                else:
                    logging.info(f'Could not find policy: {policy_arn} into role: {role_name}')
                    if role_name not in policies_to_add_on_role:
                        # Create a new list of policy_arns for the role_name
                        empty_list: list[str] = []
                        policies_to_add_on_role[role_name] = empty_list
                    policies_to_add_on_role[role_name].append(policy_arn)

        #print(instance_profiles)
        #print(role_policies)
        #print(policies_to_add_on_role)
        
        # Add policies to roles
        for role_name, policy_arns in policies_to_add_on_role.items():
            for policy_arn in policy_arns:
                logging.info(f'Adding policy: {policy_arn} to role: {role_name}')
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                roles_updated.append(f'{role_name} - {policy_arn}')

        if INSTANCE_PROFILE_NAME:
            logging.info(f'Get instance profile: {INSTANCE_PROFILE_NAME}')
            response = iam_client.get_instance_profile(InstanceProfileName=INSTANCE_PROFILE_NAME)
            logging.info(f'Got instance profile: {INSTANCE_PROFILE_NAME}')
            logging.debug(f'Response: {response}')
            instance_profile = response['InstanceProfile']
            instance_profile_association={
                'Arn': instance_profile['Arn'],
                'Name': instance_profile['InstanceProfileName']
            }

            # Get instances without a configured instance profile
            instances_without_profile = get_instances_without_profile(instances)

            #print(instances_without_profile)
            # Add the instance profile to the instances
            for instance_id in instances_without_profile:
                logging.info(f'Adding instance profile to instance: {instance_id}, profile: {instance_profile_association}')
                response = ec2_client.associate_iam_instance_profile(IamInstanceProfile=instance_profile_association, InstanceId=instance_id)
                logging.info(f'Added instance profile: {instance_profile_association} to instance: {instance_id}')
                logging.debug(f'Response: {response}')
                instances_updated.append(instance_id)
    except Exception as error:
        logging.exception(error)
        raise error

    return_dict = {'role_updated': roles_updated, 'instance_updated': instances_updated}
    logging.info(f'Function return: {return_dict}')
    logging.info('lambda_handler end')
    return return_dict


if __name__ == '__main__':
    lambda_handler(None, None)
