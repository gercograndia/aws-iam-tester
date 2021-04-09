# Testing AWS IAM policies

## Introduction

AWS IAM policies are notouriously complex, it is too easy to add some unintended permissions and it is surprisingly difficult to identify these in heavily used AWS accounts.

Thankfully AWS has provided an [IAM simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) that allows you to evaluate existing or new policies for its behavior. Which is very nice, but doing this manually is quite time consuming and it is unrealistic to test the entire environment for what you are trying to do.

However, in good AWS spirit the simulator has an API and this tool provides automation on top of it. It allows you to define the complete list of actions you want to evaluate against what resources, which allows you to run these tests on a regular basis or (better) integrate it in your CI/CD pipeline.

## Testing approach

The testing leverages AWS' [IAM simulator (api)](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html), that basically includes the same IAM evaluation logic that is applied when working in the console or using the cli. The beneits of this approach are:

- It takes all different levels of policies into account. Think about permission boundaries, service control policies and so on.
- It is an official service from AWS, so you can expect this to kept up to date over time.
- The actual actions are evaluated, but NOT executed. Hence no need for cleaning up resources after testing.

# Quick testing

For convenience, you can use this tool to quickly test whether a user has a specific permission on a particular resource:

```bash
$ aws-iam-tester access -u the_user -a 'glue:DeleteTable'
Test:
Source:     arn:aws:iam::208912673223:user/the_user
Action:     glue:DeleteTable
Resource:   *
Result:     allowed

Matched statements:
Policy:     admin_permissions
Type:       IAM Policy
Start:      L3:C17
End:        L8:C6
```

Or to see who has access to a particular resource and action by omitting both `user` and `role`:

```bash
$ aws-iam-tester access -a "s3:PutObject"
..............

Summary:

| Source                                                   | Action       | Resource   | Decision   | Policies            |
|----------------------------------------------------------|--------------|------------|------------|---------------------|
| arn:aws:iam::XXXXXXXXXXXX:user/the_user                  | s3:PutObject | *          | allowed    | admins_permissions  |
| arn:aws:iam::xxxxxxxxxxxx:role/the_role                  | s3:PutObject | *          | allowed    | AdministratorAccess |
```

## Finding out who has access to a particular action/resource combination

It might be useful to check your highly senstive resources and find out who exactly can access these. 

```bash
$ aws-iam-tester access -a "s3:PutObject" -R "arn:aws:s3:::my-strictly-confidential-data"
..............

Summary:

| Source                                                   | Action       | Resource                                   | Decision   | Policies            |
|----------------------------------------------------------|--------------|--------------------------------------------|------------|---------------------|
| arn:aws:iam::XXXXXXXXXXXX:user/the_user                  | s3:PutObject | arn:aws:s3:::my-strictly-confidential-data | allowed    | admins_permissions  |
| arn:aws:iam::xxxxxxxxxxxx:role/the_role                  | s3:PutObject | arn:aws:s3:::my-strictly-confidential-data | allowed    | AdministratorAccess |
```

# Account testing

However, the initial purpose of this tool is to check an entire account whether there are no users and/or roles having permissons which they should not have.

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

### Using a dynamic account id in the resource arn

In case you **need** to specify the `account id` in the resource arn, you can specificy this as follows:

```yaml
- actions:
  - "secretsmanager:GetSecretValue"
  expected_result: succeed
  resources:
  - "arn:aws:secretsmanager:eu-central-1:{account_id}:secret:my-secret/*"
```

### Using regular expressions for user and role matching

Regular expressions can be used when checking the users and/or roles that need to be included in the tests. Hence they are supported for the following elements in the config file:

- limit_to (the filtered list of users/roles to be used for a particular test)
- global_limit_to (the filtered list of users/roles to be used for all tests)
- exemptions (the filtered list of users/roles that should be excluded from a particular test)
- global_exemptions (the filtered list of users/roles that should be excluded from all tests)

> For all other elements, regular expression matching is NOT supported!

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

## Return codes

The tester returns the following return codes:

- 0 upon successful completion with NO findings
- 1 upon successful completion with findings
- 2 (or higher) on failures

## Required permissions

Obviously the client has to run under an AWS security context that has sufficient permissions to query the IAM resources and run the simulator.

The following permissions are needed at the minimum:

```yaml
- sts:GetCallerIdentity
- iam:ListAccountAliases
- iam:ListRoles
- iam:ListUsers
- iam:SimulatePrincipalPolicy
```

And if you want to write the output to an s3 location, then obviously you need write access (`s3:PutObject`) to that particular location as well.

## Unit testing

`pytest` is being used for testing the various options.

As long as the `aws-iam-tester` module is installed, you can run the [tests](./tests).

After installing `tox`, you can also simply run `$ tox`.