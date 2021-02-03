##############################################################
#
# lambda_stack.py
#
# Resources:
#  2 lambda functions (code in /lambda folder (from_asset))
#    - root_no_access_key
#    - iam_unused_keys
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  aws_lambda as lambda_,
  core
)

class LambdaStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, config_lambda_role: iam.IRole, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get acct id for policies
    #acct_id=env['account']
    
    
    # create the config root no access key Lambda function
    self._config_root_no_access_key_function=lambda_.Function(self,"Root No Key Lambda Func",
      code=lambda_.Code.from_asset("lambda/root_no_access_key.zip"),
      handler="root_no_access_key.lambda_handler",
      runtime=lambda_.Runtime.PYTHON_3_8,
      role=config_lambda_role,
      timeout=core.Duration.seconds(180)
    )

    # create the config unused access keys Lambda function
    self._config_iam_unused_keys_function=lambda_.Function(self,"IAM Unused Access Keys Lambda Func",
      code=lambda_.Code.from_asset("lambda/iam_unused_keys.zip"),
      handler="iam_unused_keys.lambda_handler",
      runtime=lambda_.Runtime.PYTHON_3_8,
      role=config_lambda_role,
      timeout=core.Duration.seconds(180)
    )

  # Exports
  @property
  def config_root_no_access_key_function(self) -> lambda_.IFunction:
    return self._config_root_no_access_key_function

  @property
  def config_iam_unused_keys_function(self) -> lambda_.IFunction:
    return self._config_iam_unused_keys_function




