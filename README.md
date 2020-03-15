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

## How to use

To run and write the outputs to the local `./results` directory:

```bash
./aws-iam-tester.py --write-to-file
```

Or print debug output:

```bash
./aws-iam-tester.py --debug
```

To run a limited number of evaluations (which helps speeding things up, and avoiding API throttling issues):

```bash
./aws-iam-tester.py --number-of-runs 10
```

For more information, run `./aws-iam-tester.py --help` for more instructions.