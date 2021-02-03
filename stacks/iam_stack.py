##############################################################
#
# iam_stack.py
#
# Resources:
#   Config Lambda Execution Role
#
# Exports:
#  config_lambda_role
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  core
)

class IAMStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, proj, env, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get region for role name
    region=env['region']
    # get acct id for resource
    acct_id=env['account']

    # create lambda execution role
    self._config_lambda_role=iam.Role(self,"Config Lambda Role",
      role_name=proj+"_Lambda_Execution_Role-"+region,
      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
      inline_policies=[iam.PolicyDocument(
        statements=[iam.PolicyStatement(
          actions=[
            "iam:GetUser",
            "iam:GetAccessKeyLastUsed"
          ],
          effect=iam.Effect.ALLOW,
          resources=["arn:aws:iam::"+acct_id+":user/*"]
        )]
      )],
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('job-function/ViewOnlyAccess'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSConfigRulesExecutionRole')
      ]
    ).without_policy_updates()

  # Exports
  @property
  def config_lambda_role(self) -> iam.IRole:
    return self._config_lambda_role