#!/usr/bin/env python3

###################################################################
#
# 1. IAM Stack
#
# 2. Lambda Stack
# 
# 3. Config Stack
# 
# Note: IAM specific, ergo run from us-east-1
#  
###################################################################

from aws_cdk import core

import boto3
import sys

client = boto3.client('sts')
region=client.meta.region_name

if region != 'us-east-1':
  print("*********************************************")
  print("* !!!!!!!! ERROR !!!!!!!!")
  print("* This app may only be run from us-east-1")
  print("* IAM is specific to us-east-1")
  print("*********************************************")
  raise Exception('Error: You are using:', region, 'relaunch from us-east-1')

account_id = client.get_caller_identity()["Account"]

my_env = {'region': 'us-east-1', 'account': account_id}

from stacks.iam_stack import IAMStack
from stacks.lambda_stack import LambdaStack
from stacks.config_stack import ConfigStack

proj_name="config-iam-best"

app = core.App()

iam_stack=IAMStack(app, proj_name+"-iam",proj=proj_name,env=my_env)
lambda_stack=LambdaStack(app, proj_name+"-lambda",
  config_lambda_role=iam_stack.config_lambda_role
)
config_stack=ConfigStack(app,proj_name+"-config",
  config_root_no_access_key_function=lambda_stack.config_root_no_access_key_function,
  config_iam_unused_keys_function=lambda_stack.config_iam_unused_keys_function
)

app.synth()
