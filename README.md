# Testing AWS IAM policies

## Introduction

AWS IAM policies are notouriously complex, it is too easy to add some unintended permissions and it is surprisingly difficult to identify these in heavily used AWS accounts.

Even more surprisingly I couldn't find a ready-to-use utility that I could leverage.

Hence I created one myself.

## Testing approach

The testing leverages AWS' [IAM simulator (api)](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html), that basically includes the same IAM evaluation logic that is applied when working in the console or using the cli. The beneits of this approach are:

- It takes all different levels of policies into account. Think about permission boundaries, service control policies and so on.
- It is an official service from AWS, so you can expect this to kept up to date over time.
- The actual actions are evaluated, but NOT executed. Hence no need for cleaning up resources after testing.

## Configuration

In order to run, a configuration of the tests to run is required.

A sample configuration (with only one test) is shown, in various steps.

First there is a global section where you define settings which are applied to all tests (unless overruled, more on that later).

```yaml
---
user_landing_account: 0123456789 # ID of AWS Account that is allowed to assume roles in the test account
global_exemptions: # The roles and/or users below will be ignored in all tests. Regular expressions are supported
- "^arn:aws:iam::(\\d{12}):user/(.*)(ADMIN|admin)(.*)$"
- "^arn:aws:iam::(\\d{12}):role/(.*)(ADMIN|admin)(.*)$"
- "^arn:aws:iam::(\\d{12}):role/AWSCloudFormationStackSetExecutionRole$"
```

Then you define a list of tests, each consisting at least of a set of:
- actions
- resources
- the expected result (should it fail or succeed)

```yaml
# List of tests to execute. In general the configurations follow the rules of the AWS IAM Policy Simulator.
# For more information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
tests: 
- actions: # list of actions to validate
  - "*:*"
  - iam:*
  - iam:AddUser*
  - iam:Attach*
  - iam:Create*
  - iam:Delete*
  - iam:Detach*
  - iam:Pass*
  - iam:Put*
  - iam:Remove*
  - iam:UpdateAccountPasswordPolicy
  - sts:AssumeRole
  - sts:AssumeRoleWithSAML
  expected_result: fail # 'fail' or 'succeed'
  resources: # list of resources to validate against
  - "*"
```

Rather than using all users and roles (without exemptions) you can also limit your test to a particular set of users and roles.

The test below does that, including defining a custom context that specifies multi factor authentication is disabled when running the test. By default the context under which the simulations are run assumes MFA is enabled, but you can override that with the `custom_context` element. For more information see the [AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html).

```yaml
- actions: # Same list of actions, but now check (with a custom context) whether
  - "*:*"
  - iam:*
  - iam:AddUser*
  - iam:Attach*
  - iam:Create*
  - iam:Delete*
  - iam:Detach*
  - iam:Pass*
  - iam:Put*
  - iam:Remove*
  - iam:UpdateAccountPasswordPolicy
  - sts:AssumeRole
  - sts:AssumeRoleWithSAML
  expected_result: fail # 'fail' or 'succeed'
  resources: # list of resources to validate against
  - "*"
  limit_to: # check this list for the admin users
  - "^arn:aws:iam::(\\d*):user/(.*)(ADMIN|admin)(.*)$"
  - "^arn:aws:iam::(\\d*):role/(.*)(ADMIN|admin)(.*)$"
  # test if the admins are required to use multi factor authentication
  custom_context: 
    - context_key_name: aws:MultiFactorAuthPresent
      context_key_values: false
      context_key_type: boolean
```

Or if you want to do that for **all** tests you can use the `global_limit_to`:

```yaml
---
user_landing_account: 0123456789 # ID of AWS Account that is allowed to assume roles in the test account
global_limit_to: # These roles and/or users below will be u. Regular expressions are supported
- "^arn:aws:iam::(\\d{12}):user/(.*)(ENGINEER|engineer)(.*)$"
- "^arn:aws:iam::(\\d{12}):role/(.*)(SCIENTIST|scientist)(.*)$"
```

Below an example where an additional set of roles is exempt from testing:

```yaml
- actions: # list of data centric actions
  - redshift:GetClusterCredentials
  - redshift:JoinGroup
  - rds:Create*
  - rds:Delete*
  - rds:Modify*
  - rds-db:connect
  - s3:BypassGovernanceRetention
  - s3:CreateBucket
  - s3:DeleteBucket
  - s3:DeleteBucketPolicy
  - s3:PutBucketAcl
  - s3:PutBucketPolicy
  - s3:PutEncryptionConfiguration
  - s3:ReplicateDelete
  expected_result: fail # 'fail' or 'succeed'
  resources: # list of resources to validate against
  - "*"
  exemptions: [
  - "^arn:aws:iam::(\\d{12}):role/(.*)_worker$" # ignore this for the worker roles
  ]
```

If you want to run positive tests (i.e. tests that you need to succeed rather than fail), these `exemptions` don't work that well.

In that case you can limit your tests to a set of roles and users:

```yaml
- actions:
  - s3:PutObject
  expected_result: succeed
  resources:
  - "arn:aws:s3:::my_bucket/xyz/*"
  limit_to: # if you specify this, test will only be performed for the sources below
  - "^arn:aws:iam::(\\d{12}):role/my_worker$"
```

> Note that the exemptions are ignored when using a `limit_to` list.

## How to use

Assuming you have define a config.yml in your local directory, then to run and write the outputs to the local `./results` directory:

```bash
aws-iam-tester --write-to-file
```

Using a specific config file:

```bash
aws-iam-tester --config-file my-config.yml
```

Using a specific output location:

```bash
aws-iam-tester --output-location /tmp
```

Or write to s3:

```bash
aws-iam-tester --output-location s3://my-bucket/my-prefix
```

Include only roles that can be assumed by human beings:

```bash
aws-iam-tester --no-include-system-roles
```

> Note: including system roles does NOT include the aws service roles.

Or print debug output:

```bash
aws-iam-tester --debug
```

To run a limited number of evaluations (which helps speeding things up, and avoiding API throttling issues):

```bash
aws-iam-tester --number-of-runs 10
```

For more information, run `aws-iam-tester --help` for more instructions.

## Unit testing

`pytest` is being used for testing the various options.

As long as the `aws-iam-tester` module is installed, you can run the [tests](./tests).

After installing `tox`, you can also simply run `$ tox`.