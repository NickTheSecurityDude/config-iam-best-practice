##############################################################
#
# config_stack.py
#
# Resources:
#   4 Managed Config Rules
#     - access-keys-rotated-cdk
#     - mfa-enabled-for-iam-console-access-cdk
#     - iam-user-unused-credentials-check-cdk
#     - root-account-mfa-enabled-cdk
#
#   2 Custom Config Rules
#     - root-no-access-key
#     - iam-unused-keys
#
##############################################################

from aws_cdk import (
  aws_config as config,
  aws_lambda as lambda_,
  core
)

class ConfigStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, 
               config_root_no_access_key_function: lambda_.IFunction, 
               config_iam_unused_keys_function: lambda_.IFunction,
               **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # Top Risk #4
    # access-keys-rotated
    # iam-user-unused-credentials-check
    # mfa-enabled-for-iam-console-access
    # root-account-mfa-enabled
    # python/ROOT_NO_ACCESS_KEY
    # python/iam_unused_keys.py - (AWS version doesn't work, I wrote a custom function instead)

    # access-keys-rotated-cdk
    config.ManagedRule(self,"Access Keys Rotated",
      config_rule_name="access-keys-rotated-cdk",
      identifier="ACCESS_KEYS_ROTATED",
      input_parameters={
        'maxAccessKeyAge': '90',
      }
    )

    # mfa-enabled-for-iam-console-access-cdk
    config.ManagedRule(self,"IAM MFA for Console",
      config_rule_name="mfa-enabled-for-iam-console-access-cdk",
      identifier="MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.IAM_USER
      ])
    )

    # iam-user-unused-credentials-check-cdk
    config.ManagedRule(self,"IAM Unused Creds",
      config_rule_name="iam-user-unused-credentials-check-cdk",
      identifier="IAM_USER_UNUSED_CREDENTIALS_CHECK",
      input_parameters={
        'maxCredentialUsageAge': '90',
      },
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.IAM_USER
      ])
    )

    # root-account-mfa-enabled-cdk
    config.ManagedRule(self,"MFA for root",
      config_rule_name="root-account-mfa-enabled-cdk",
      identifier="ROOT_ACCOUNT_MFA_ENABLED"
    )

    # python/ROOT_NO_ACCESS_KEY
    config.CustomRule(self,"Root No Access Key Config Rule",
      config_rule_name="root-no-access-key",
      lambda_function=config_root_no_access_key_function,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.ONE_HOUR
    )

    # python/iam_unused_keys.py
    # Description: Checks that all users have only active access keys.
    # Only check users over MinimumAge days old, default 30
    config.CustomRule(self,"Unused Keys Config Rule",
      config_rule_name="iam-unused-keys",
      lambda_function=config_iam_unused_keys_function,
      configuration_changes=True,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.ONE_HOUR,
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.IAM_USER
      ]),
      input_parameters={
        'MinimumAge': '30',
      }
    )
