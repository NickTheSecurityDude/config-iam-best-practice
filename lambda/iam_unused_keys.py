# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  iam-unused-keys
Description:
  Check for unused keys over X days old. This does NOT check for keys which were 
  used previously and now are inactive, there is a different rule for that.
Note:
  This is a rewrite of the aws provided config rule with the same name located here:
    https://github.com/awslabs/aws-config-rules/blob/master/python/iam_unused_keys.py
  This script contains the following improvements:
    - the AWS one doesn't/no longer works and it appears its not maintained
    - this one uses the RDK format, including helper functions
    - it works for both periodic and configuration changes
        the AWS only worked on changes, which I'm not sure would occur for an unused access key
    - this one is scalable and implements pagination for the IAM users
    - it allows a parameter for MinimumAge, so your not reporting users just created as NON_COMPLIANT
        validation is done on the parameter to ensure its value is valid
    - this one can be easily launched, along with all related stacks, via CDK
Trigger:
  Periodic
  Configuration Change on AWS::IAM::User
Reports on:
  AWS::IAM::User
Parameters:
  | ----------------------|-----------|--------------------------------------------------------------|
  | Parameter Name        | Type      | Description                                                  |
  | ----------------------|-----------|------------------------------------------------------------- |
  | MinimumAge            | Required  | Skip users less than "MinimumAge" days old. (Default: 30)    |
  | ----------------------|-----------|------------------------------------------------------------- |

Feature:
    In order to: help prevent the leak of access keys
             As: a Security Officer
         I want: to remove keys which are not being used.
        
Scenarios:
    Scenario 1:
      Given: MinimumAge parameter is not a number
       Then: return ERROR
    Scenario 2:
      Given: MinimumAge parameter is less than 1 or greater than 365
       Then: return ERROR
    Scenario 3:
      Given: user is less than MinimumAge days old
       Then: return NOT_APPLICABLE
    Scenario 4:
      Given: user has an access key which hasn't been used and user is over MinimumAge days old
       Then: return NON_COMPLIANT
    Scenario 5:
      Given: user has an access key and that key has been used
       Then: return COMPLIANT
'''


import json
import sys
import datetime
import boto3
import botocore
from datetime import datetime, timedelta
import dateutil.parser

try:
    import liblogging
except ImportError:
    pass

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900

####################
# Global Variables #
####################

iam_client = boto3.client('iam')

evaluations=[]

#############
# Functions #
#############

# Function to get age of user (skip if younger than X days)
def user_age_(create_date):
  # return age of user
  today = datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())
  time_delta = today - create_date

  return time_delta    

# Function to check the date of the access key(s) of a particular user
def check_access_key(_principal,_min_age):

  # default is compliant
  _compliance="COMPLIANT"

  # check age of use, skip users under "MinimumAge"
  response3 = iam_client.get_user(
    UserName=_principal
  )
  create_date=response3['User']['CreateDate']
  user_age=user_age_(create_date)
  if DEBUG:
    print(user_age)

  expiry_time = timedelta(days=_min_age)
  if DEBUG:
    print("Exp time:",expiry_time)

  # if user is "new" return NA
  if user_age < expiry_time:
    if DEBUG:
      print("young user")
    _compliance="NOT_APPLICABLE"
  else:
    # check access key last used date
    response = iam_client.list_access_keys(
      UserName=_principal,
    )
    keys=response['AccessKeyMetadata']
    # users may have up to 2 keys, check them both
    for key in keys:
      key_id=key['AccessKeyId']
      response2 = iam_client.get_access_key_last_used(
        AccessKeyId=key_id
      )
      # if there was no "LastUsedDate" it will give an error
      try:
        last_used=response2['AccessKeyLastUsed']['LastUsedDate']
        if DEBUG:
          print(last_used)
      except:
        # if error, catch and return NC
        if DEBUG:
          print("UNUSED KEY FOR USER:",_principal)
        _compliance="NON_COMPLIANT"

  return _compliance

#############
# Main Code #
#############

DEBUG=0

def evaluate_compliance(event, configuration_item, valid_rule_parameters):

  if DEBUG:
    print("Event (Line 173):",event)

  # get min_age from param and convert from string to int
  min_age=int(valid_rule_parameters['MinimumAge'])

  # check if this is a period run (loop through all users, groups, and roles) or a run based on a change      
  try:
    periodic_test=json.loads(event['invokingEvent'])['configurationItem']
    periodic=0
    print("Configuration Change Run")
  except Exception as e:
    if DEBUG:
      print(e)
    print("Periodic Run")
    periodic=1

  # paginate users to support more than 100
  if periodic:
    p = iam_client.get_paginator('list_users')
    paginator=p.paginate()
    for page in paginator:
      for user in page['Users']:
        principal=user['UserName']
        if DEBUG:
          print("Principal:",principal)

        # get user's compliance status
        compliance=check_access_key(principal,min_age)
        # add results to evaluations array
        user_id=user['UserId']
        evaluations.append(build_evaluation(user_id, compliance, event,annotation=principal))

    return evaluations
  else:
    # if single run check just the one principal (get it from the configuration item)
    #resource_type=configuration_item['resourceType']
    principal=configuration_item['resourceName']
    if DEBUG:
      print("Principal:",principal)
    return check_access_key(principal,min_age)

# make sure a number was entered
def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """
    # print parameters if in DEBUG mode
    if DEBUG:
      print("eval_param ma:",rule_parameters['MinimumAge'])

    if rule_parameters:
      # check int parameter
      minimum_age=rule_parameters['MinimumAge']
      if DEBUG:
        print("Checking int (Line 233)")
        print(type(minimum_age))
      try:
        minimum_age=int(minimum_age)
        # a key over 1 year old kinda defaults the purpose of this rule so give and error
        # a key 0 days old or a negative number is not appropriate as well
        if minimum_age < 1 or minimum_age > 365:
          raise ValueError('MinimumAge must be between 1 and 365')
      except:
        raise ValueError('MinimumAge parameter needs to be an integer (no quotes).')
    else:
      print("rule_parameters is False")

    valid_rule_parameters = rule_parameters

    if DEBUG:
      print("Exiting evaluate_parameters")
      
    return valid_rule_parameters

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internal_error_message="Parameter value is invalid",
                                 internal_error_details="An ValueError was raised during the validation of the Parameter value",
                                 customer_error_code="InvalidParameterValueException",
                                 customer_error_message=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event, region=None):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    region -- the region where the client is called (default: None)
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service, region)
    credentials = get_assume_role_credentials(get_execution_role_arn(event), region)
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = build_annotation(annotation)
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on configuration change rules.

    Keyword arguments:
    configuration_item -- the configurationItem dictionary in the invokingEvent
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = build_annotation(annotation)
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

####################
# Boilerplate Code #
####################

# Get execution role for Lambda function
def get_execution_role_arn(event):
    role_arn = None
    if 'ruleParameters' in event:
        rule_params = json.loads(event['ruleParameters'])
        role_name = rule_params.get("ExecutionRoleName")
        if role_name:
            execution_role_prefix = event["executionRoleArn"].split("/")[0]
            role_arn = "{}/{}".format(execution_role_prefix, role_name)

    if not role_arn:
        role_arn = event['executionRoleArn']

    return role_arn

# Build annotation within Service constraints
def build_annotation(annotation_string):
    if len(annotation_string) > 256:
        return annotation_string[:244] + " [truncated]"
    return annotation_string

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'ScheduledNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configuration_item = result['configurationItems'][0]
    return convert_api_configuration(configuration_item)

# Convert from the API model to the original invocation model
def convert_api_configuration(configuration_item):
    for k, v in configuration_item.items():
        if isinstance(v, datetime.datetime):
            configuration_item[k] = str(v)
    configuration_item['awsAccountId'] = configuration_item['accountId']
    configuration_item['ARN'] = configuration_item['arn']
    configuration_item['configurationStateMd5Hash'] = configuration_item['configurationItemMD5Hash']
    configuration_item['configurationItemVersion'] = configuration_item['version']
    configuration_item['configuration'] = json.loads(configuration_item['configuration'])
    if 'relationships' in configuration_item:
        for i in range(len(configuration_item['relationships'])):
            configuration_item['relationships'][i]['name'] = configuration_item['relationships'][i]['relationshipName']
    return configuration_item

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invoking_event):
    check_defined(invoking_event, 'invokingEvent')
    if is_oversized_changed_notification(invoking_event['messageType']):
        configuration_item_summary = check_defined(invoking_event['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configuration_item_summary['resourceType'], configuration_item_summary['resourceId'], configuration_item_summary['configurationItemCaptureTime'])
    if is_scheduled_notification(invoking_event['messageType']):
        return None
    return check_defined(invoking_event['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configuration_item, event):
    try:
        check_defined(configuration_item, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configuration_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")

    return status in ('OK', 'ResourceDiscovered') and not event_left_scope


def get_assume_role_credentials(role_arn, region=None):
    sts_client = boto3.client('sts', region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn,
                                                      RoleSessionName="configLambdaExecution",
                                                      DurationSeconds=CONFIG_ROLE_TIMEOUT_SECONDS)
        if 'liblogging' in sys.modules:
            liblogging.logSession(role_arn, assume_role_response)
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        print(str(ex))
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evaluations = []

    old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'],
        ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
        Limit=100)

    old_eval_list = []

    while True:
        for old_result in old_eval['EvaluationResults']:
            old_eval_list.append(old_result)
        if 'NextToken' in old_eval:
            next_token = old_eval['NextToken']
            old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
                ConfigRuleName=event['configRuleName'],
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
                Limit=100,
                NextToken=next_token)
        else:
            break

    for old_eval in old_eval_list:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evaluations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evaluations + latest_evaluations

def lambda_handler(event, context):
    if 'liblogging' in sys.modules:
        liblogging.logEvent(event)

    global AWS_CONFIG_CLIENT

    if DEBUG:
      print("Event (Line 481):",event)
    check_defined(event, 'event')

    # this should only error if you test the lambda function with invalid json
    invoking_event = json.loads(event['invokingEvent'])
    
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    try:
        valid_rule_parameters = evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        AWS_CONFIG_CLIENT = get_client('config', event)
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
            configuration_item = get_configuration_item(invoking_event)
            if is_applicable(configuration_item, event):
                if DEBUG:
                  print("configuration item (Line 501)",configuration_item)
                compliance_result = evaluate_compliance(event, configuration_item, valid_rule_parameters)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'], ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))

    evaluations = []
    latest_evaluations = []

    if not compliance_result:
        latest_evaluations.append(build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account'))
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, str):
        if configuration_item:
            evaluations.append(build_evaluation_from_config_item(configuration_item, compliance_result))
        else:
            evaluations.append(build_evaluation(event['accountId'], compliance_result, event, resource_type=DEFAULT_RESOURCE_TYPE))
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE'))

    # Put together the request that reports the evaluation status
    result_token = event['resultToken']
    test_mode = False
    if result_token == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        test_mode = True

    # Invoke the Config API to report the result of the evaluation
    evaluation_copy = []
    evaluation_copy = evaluations[:]
    while evaluation_copy:
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=result_token, TestMode=test_mode)
        del evaluation_copy[:100]

    # Used solely for RDK test to be able to test Lambda function
    return evaluations

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internal_error_message, internal_error_details=None):
    return build_error_response(internal_error_message, internal_error_details, 'InternalError', 'InternalError')

def build_error_response(internal_error_message, internal_error_details=None, customer_error_code=None, customer_error_message=None):
    error_response = {
        'internalErrorMessage': internal_error_message,
        'internalErrorDetails': internal_error_details,
        'customerErrorMessage': customer_error_message,
        'customerErrorCode': customer_error_code
    }
    print(error_response)
    return error_response