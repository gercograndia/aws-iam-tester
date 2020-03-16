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

A sample configuration (with only one test) is shown below.

```yaml
---
user_landing_account: 0123456789 # ID of AWS Account that is allowed to assume roles in the test account
global_exemptions: # The roles and/or users below will be ignored in all tests. Regular expressions are supported
- "^arn:aws:iam::(\\d{12}):user/(.*)(ADMIN|admin)(.*)$"
- "^arn:aws:iam::(\\d{12}):role/(.*)(ADMIN|admin)(.*)$"
- "^arn:aws:iam::(\\d{12}):role/AWSCloudFormationStackSetExecutionRole$"
# List of tests to execute. In general the configurations follow the rules of the AWS IAM Policy Simulator.
# For more information: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
tests: 
- actions: # list of actions to validate
  - "*:*"
  - iam:*
  - iam:Create*
  - iam:Pass*
  - sts:AssumeRole
  - sts:AssumeRoleWithSAML
  expected_result: fail # 'fail' or 'succeed'
  resources: # list of resources to validate against
  - "*"
  exemptions: [] # Additional exemptions (on top of the global excemptions) that will be ignored for this test
```

## How to use

Assuming you have define a config.yml in your local directory, then to run and write the outputs to the local `./results` directory:

```bash
aws-iam-tester --write-to-file
```

Using a specific config file:

```bash
aws-iam-tester --config-file my-config.yml
```

Or print debug output:

```bash
aws-iam-tester --debug
```

To run a limited number of evaluations (which helps speeding things up, and avoiding API throttling issues):

```bash
aws-iam-tester --number-of-runs 10
```

For more information, run `aws-iam-tester --help` for more instructions.