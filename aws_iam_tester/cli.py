#! /usr/bin/env python3

"""
AWS IAM policies are notouriously complex, it is too easy to add some unintended
permissions and it is surprisingly difficult to identify these in heavily used AWS accounts.

Thankfully AWS has provided an IAM simulator that allows you to evaluate existing or
new policies for its behavior. Which is very nice, but doing this manually is quite
time consuming and it is unrealistic to test the entire environment for what you are
trying to do.

However, in good AWS spirit the simulator has an API and this tool provides automation
on top of it. It allows you to define the complete list of actions you want to evaluate
against what resources, which allows you to run these tests on a regular basis or (better)
integrate it in your CI/CD pipeline.
"""

# pylint: disable=broad-except,C0103,E0401,R0912,R0913,R0914,R0915,R1702,W0603,W1203

import os
import sys
import errno
import json
import logging
import re
import time
import yaml
import click
import boto3 # type: ignore
import botocore # type: ignore

from typing import Dict, List, Tuple, Optional, Any
from termcolor import colored
from outdated import check_outdated # type: ignore

from . import __version__

# Defaults
DEFAULT_SLEEP_SECONDS = 300

logger: logging.Logger

# define boto3 retry logic, as the simulation api might do some throttling
boto3_config = botocore.config.Config(
    retries=dict(
        max_attempts=10
    )
)

@click.command()
@click.option(
    '--number-of-runs', '-n',
    help='Run only a limited number of simulations, and then abort.',
    type=int,
    default=-1
    )
@click.option(
    '--dry-run', '-D',
    help='Dry run mode will not run the actual policy simulations. Default: False',
    is_flag=True,
    default=False
    )
@click.option(
    '--config-file', '-c',
    help='Config file location. Default: config.yml.',
    default='config.yml'
    )
@click.option(
    '--include-system-roles', '-i',
    help='Include non-user-assumable system roles. Default: True',
    is_flag=True,
    default=True
    )
@click.option(
    '--write-to-file', '-w',
    help='Write results to file.',
    is_flag=True,
    default=False
    )
@click.option(
    '--output-location', '-o',
    help='Output location, either s3 (start with s3://) or locally. Default: ./results',
    default='./results'
    )
@click.option(
    '--debug', '-d',
    help='Print debug messages.',
    is_flag=True,
    default=False
    )
@click.version_option(version=__version__)
def main(
        number_of_runs: int,
        dry_run: bool,
        config_file: str,
        include_system_roles: bool,
        write_to_file: bool,
        output_location: str,
        debug: bool
    ) -> int:
    """
    Run the IAM policy tests.

    Based on the findings the following return values will be generated:
     0: Upon successful completion with NO findings
    -1: Upon successful completion with findings
     1: Upon failures
    """

    def convert_context_dict(my_dict: Dict) -> Dict:
        result = {}
        for key, value in my_dict.items():
            # convert key to CamelCase
            if isinstance(key, str):
                new_key = ''.join(x.capitalize() or '_' for x in key.split('_'))
                result[new_key] = value

                # the ContextKeyValues should be a list
                if new_key == 'ContextKeyValues':
                    result[new_key] = [value]
            else:
                result[key] = value

        # convert boolean values to strings
        if result['ContextKeyType'] == 'boolean':
            result['ContextKeyValues'] = [str(x).lower() for x in result['ContextKeyValues']]

        return result

    global logger
    logger = setup_logger(
        debug=debug,
    )

    # check for newer versions
    try:
        is_outdated, latest_version = check_outdated('aws-iam-tester', __version__)
        if is_outdated:
            click.echo(
                f'Your local version ({__version__}) is out of date! Latest is {latest_version}!'
            )
    except ValueError:
        # this happens when your local version is ahead of the pypi version,
        # which happens only in development
        pass

    try:
        # first get current account id
        try:
            sts_client = boto3.client("sts")
            account_id = sts_client.get_caller_identity()["Account"]
        except botocore.exceptions.ClientError as ce:
            if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
            else:
                logger.exception(ce)
            sys.exit(1)

        # try to get the friendly account name
        iam_client = boto3.client("iam")
        try:
            account_alias = iam_client.list_account_aliases(MaxItems=1)["AccountAliases"][0]
        except (KeyError, IndexError):
            account_alias = account_id
        except botocore.exceptions.ClientError as ce:
            if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
            else:
                logger.exception(ce)
            sys.exit(1)

        config, global_exemptions, global_limit_to, user_landing_account = read_config(config_file)

        logger.debug("dynamically collect users and roles")
        users = get_iam_users()
        roles = get_iam_roles(
            user_landing_account=user_landing_account,
            my_account=account_id,
            include_system_roles=include_system_roles
            )

        sources = []
        sources.extend(users)
        sources.extend(roles)
        len_1 = len(sources)

        # If we have a global_limit_to, reduce the full set of sources
        # to only that in order to improve performance
        if global_limit_to:
            filtered_sources = []
            for limit in global_limit_to:
                compiled = re.compile(limit)
                filtered_list = [s for s in sources if compiled.match(s)]
                filtered_sources.extend(filtered_list)
            # Now remove duplicates
            sources = list(set(filtered_sources))
            logger.debug(f"Number of sources limited from {len_1} to {len(sources)}")

        # If we have a global_exemptions, remove these from the sources as well
        if global_exemptions:
            exempt_sources = []
            for limit in global_exemptions:
                compiled = re.compile(limit)
                filtered_list = [s for s in sources if compiled.match(s)]
                exempt_sources.extend(filtered_list)
            # Now remove duplicates and subtract from sources list
            sources = list(set(sources) - set(exempt_sources))
            logger.debug(f"Number of sources  reduced with exemptions from {len_1} to {len(sources)}")

        results = []

        counter = 0
        logger.debug("Start checking the configs")
        for cfg in config['tests']:
            # do we need to break?
            if 0 < number_of_runs < counter:
                break

            actions = cfg["actions"]
            resources = [x.format(account_id=account_id) for x in cfg["resources"]]

            # create a full list of exemptions
            exemptions = []
            if "exemptions" in cfg:
                exemptions = cfg["exemptions"]

            # check if this test contain a 'limit_to' element
            limit_to = []
            if "limit_to" in cfg:
                limit_to = cfg["limit_to"]

            # check if the expected result has the expected values
            expected_result = cfg["expected_result"].lower()
            if expected_result not in ['fail', 'succeed']:
                raise ValueError(
                    f"The expected result should be 'fail' or 'succeed'. It is now '{expected_result}'"
                )

            expect_failures = (expected_result == "fail")
            logger.debug(f"Run config for actions: {actions} with resources {resources}")

            # check if we have a custom context
            sim_context = None
            if "custom_context" in cfg:
                custom_context = cfg["custom_context"]
                # the keys in the custom context need to be converted to CamelCase
                sim_context = []
                for ctx in custom_context:
                    c_ctx = convert_context_dict(ctx)
                    sim_context.append(c_ctx)

            for source in sources:
                if limit_to: # do we have a limit_to?
                    exempt = True
                    for limit in limit_to:
                        if re.match(limit, source):
                            exempt = False
                            break

                    if exempt and debug:
                        logger.debug(f"\nSource {source} is not included in whitelist")
                    elif exempt:
                        print(colored(".", "blue"), end="")
                        sys.stdout.flush()
                else: # or is this source exempt from testing
                    exempt = False
                    for exemption in exemptions:
                        if re.match(exemption, source):
                            exempt = True
                            if debug:
                                logger.debug(
                                    f"\nSource {source} is exempt from testing using: {exempt}"
                                )
                            else:
                                print(colored(".", "blue"), end="")
                                sys.stdout.flush()
                            break

                counter += 1
                if 0 < number_of_runs < counter:
                    print("\n")
                    logger.debug("Test run mode activated, max iterations reached.")
                    break
                if dry_run:
                    logger.debug(f"Dry run mode, no simulation for {source}")
                elif not exempt:
                    evaluation_results = simulate_policy(
                        source=source,
                        actions=actions,
                        resources=resources,
                        sim_context=sim_context,
                    )

                    if evaluation_results:
                        denies = [x for x in evaluation_results if is_denied(x)]
                        allows = [x for x in evaluation_results if not is_denied(x)]

                        if expect_failures:
                            # allows are failures
                            failures = allows
                        else:
                            # denies are failures
                            failures = denies

                        success = (len(failures) == 0)

                        if success:
                            if debug:
                                logger.debug(colored(f"Success: {source}", "green"))
                            else:
                                print(colored(".", "green"), end="")
                                sys.stdout.flush()
                        else:
                            res = construct_results(
                                source=source,
                                expect_failures=expect_failures,
                                results=failures,
                                print_results=debug,
                                )
                            results.extend(res)
                            if not debug:
                                print(colored(".", "red"), end="")
                                sys.stdout.flush()

        return_value = handle_results(
            results=results,
            write_to_file=write_to_file,
            output_location=output_location,
            account=account_alias,
        )
        sys.exit(return_value)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)

def setup_logger(debug: bool) -> logging.Logger:
    "Set up the logger"
    lgr = logging.getLogger('iam-tester')
    lgr.propagate = False
    if not lgr.handlers:
        ch = logging.StreamHandler(sys.stdout)
        if debug:
            lgr.setLevel(level=logging.DEBUG)
            ch.setLevel(level=logging.DEBUG)
        else:
            lgr.setLevel(level=logging.INFO)
            ch.setLevel(level=logging.INFO)
        formatter = logging.Formatter(
            "%(levelname)s:\t%(message)s"
        )
        ch.setFormatter(formatter)
        lgr.addHandler(ch)

    return lgr

def read_config(config_file: str) -> Tuple[Dict, List[str], List[str], Optional[str]]:
    "Read and parse config file"
    logger.debug(f"Read config file {config_file}")

    try:
        with open(config_file) as file:
            config = yaml.load(file, Loader=yaml.FullLoader)
    except IOError:
        logger.error(f"Config '{config_file}' not accessible")
        raise
    finally:
        try:
            file.close()
        except IOError:
            pass

    global_exemptions = []
    if "global_exemptions" in config:
        global_exemptions = config["global_exemptions"]

    global_limit_to = []
    if "global_limit_to" in config:
        global_limit_to = config["global_limit_to"]

    user_landing_account = None
    if "user_landing_account" in config:
        user_landing_account = config["user_landing_account"]

    return config, global_exemptions, global_limit_to, user_landing_account

def get_iam_roles(
        user_landing_account: Optional[str],
        my_account: str,
        include_system_roles: bool
    ) -> List[str]:
    "Read (and filter) the IAM roles in the account"
    client = boto3.client('iam')
    roles = []
    try:
        paginator = client.get_paginator('list_roles')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            rolelist = page["Roles"]
            for role in rolelist:
                # only get the roles that can be assumed by 'users'
                policy_doc = json.dumps(role["AssumeRolePolicyDocument"])

                if 'aws-service-role' not in role["Path"] and ( # ignore service roles
                        # accept roles that can be assumed by users in my account
                        f"arn:aws:iam::{my_account}:root" in policy_doc or
                        # accept roles that can be assumed by a dedicated user landing account
                        f"arn:aws:iam::{user_landing_account}:root" in policy_doc or
                        # accept roles that can be assumed with SAML
                        f"arn:aws:iam::{my_account}:saml-provider" in policy_doc or
                        # do we want to include non user assumable roles
                        include_system_roles
                    ):
                    roles.append(role['Arn'])

        return roles
    except botocore.exceptions.ClientError as ce:
        if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
            print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
        else:
            logger.exception(ce)
        sys.exit(1)

def get_iam_users() -> List[str]:
    "Get all IAM users"
    client = boto3.client('iam')
    users = []

    try:
        paginator = client.get_paginator('list_users')
        page_iterator = paginator.paginate()
        for page in page_iterator:
            userlist = page["Users"]
            for user in userlist:
                users.append(user['Arn'])

        return users
    except botocore.exceptions.ClientError as ce:
        if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
            print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
        else:
            logger.exception(ce)
        sys.exit(1)

def simulate_policy(
        source: str,
        actions: List[str],
        resources: List[str],
        sim_context: List[Dict] = None
        ) -> Optional[Dict]:
    """Simulate a set of actions from a specific principal against a resource"""
    def simulate(
            source: str,
            actions: List[str],
            resources: List[str],
            sim_context: List[Dict] = None
        ) -> Optional[Dict]:
        # do we have a custom context to pass along?
        if not sim_context:
            sim_context = [
                {
                    'ContextKeyName': 'aws:MultiFactorAuthPresent',
                    'ContextKeyValues': [
                        # Always test with MFA present, which is worst case scenario
                        # (as lots of rights might be revoked without MFA)
                        'true',
                    ],
                    'ContextKeyType': 'boolean',
                },
                {
                    'ContextKeyName': 'redshift:DbUser',
                    'ContextKeyValues': [
                        'admin',
                    ],
                    'ContextKeyType': 'string',
                },
            ]

        response = client.simulate_principal_policy(
            PolicySourceArn=source,
            ActionNames=actions,
            ResourceArns=resources,
            ContextEntries=sim_context,
        )
        return response["EvaluationResults"]

    client = boto3.client("iam", config=boto3_config)
    try:
        return simulate(source, actions, resources, sim_context)
    except client.exceptions.NoSuchEntityException as nsee:
        print("\n")
        logger.error(
            f"Could not find entity {source} during simulation, has it just been removed?\n{nsee}"
        )
        # but ignore it
        return None
    except client.exceptions.ClientError as ce:
        if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
            print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
            sys.exit(1)
        elif "throttling" in str(ce).lower():
            logger.error(
                colored(
                    "\nThrottling of API is requested. " +
                    f"Sleep for {DEFAULT_SLEEP_SECONDS} seconds and try again\n"
                ),
                "blue"
            )
            time.sleep(DEFAULT_SLEEP_SECONDS)
            return simulate(source, actions, resources, sim_context)
        else:
            logger.exception(ce)
            sys.exit(1)
    except Exception as e:
        logger.error(f"\nError simulating entity {source}\n{e}")
        raise

def is_denied(evaluationResults: Dict) -> bool:
    "Returns whether or not the evaluation is denied"
    return evaluationResults["EvalDecision"] != "allowed"


def construct_results(
        source: str,
        expect_failures: bool,
        results: Any,
        print_results: bool = True
    ) -> List[Dict]:
    """Constructs a dict with the results of a simulation evaluation result"""
    output = ""
    response = []
    for er in results:
        message = (
            f"\nSource: {source}\n"
            f"Must fail: {expect_failures}\n"
            f"Evaluated Action Name: {er['EvalActionName']}\n"
            f"\tEvaluated Resource name: {er['EvalResourceName']}\n"
            f"\tDecision: {er['EvalDecision']}\n"
            f"\tMatched statements: {er['MatchedStatements']}"
        )
        r = {
            "source": source,
            "action": er['EvalActionName'],
            "must_fail": expect_failures,
            "resource": er['EvalResourceName'],
            "decision": er['EvalDecision'],
            "matched_statements": er['MatchedStatements'],
        }
        response.append(r)
        output += message
    if print_results:
        print(colored(output, "red"))

    return response


def handle_results(
        results: List[Dict],
        write_to_file: bool,
        output_location: str,
        account: str
    ) -> int:
    "Print the results or write them to file"
    print("\n\n")
    logger.debug("Handle results")
    return_value = -1
    if results and write_to_file:
        timestr = time.strftime("%Y%m%d-%H%M%S")
        filename = f'results-{account}-{timestr}.json'

        # remove the trailing / if present
        output_location = output_location.rstrip('/')

        # do we need to write to s3?
        if output_location.startswith('s3://'):
            # parse the output location into bucket and key
            bucket = output_location[5:].split("/")[0]
            # do we have a prefix?
            try:
                prefix = output_location[5:].split("/", 1)[1]
            except IndexError:
                prefix = ""

            s3_client = boto3.client('s3')
            try:
                full_filename = f'{prefix}/{filename}'
                logger.debug(f"Try to write results to s3://{bucket}/{full_filename}")
                s3_client.put_object(
                    Body=json.dumps(results).encode(),
                    Bucket=bucket,
                    Key=full_filename,
                )
            except s3_client.exceptions.ClientError as ce:
                if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                    print(f"Please make sure you are logged in into AWS, with sufficient permissions. (Exception: {str(ce)})")
                else:
                    logger.exception(ce)
                sys.exit(1)
        else:
            # first ensure directory exists
            try:
                if os.path.isabs(output_location): # is output location absolute?
                    path = output_location
                else:
                    path = os.path.abspath(output_location)
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise
            try:
                full_filename = f'{path}/{filename}'
                logger.debug(f"Try to write results to local file system: {full_filename}")
                with open(full_filename, 'w') as outfile:
                    json.dump(results, outfile, indent=4)
            except IOError as e:
                logger.error(f"Could not write results to file system: {e}")
            finally:
                try:
                    outfile.close()
                except Exception:
                    pass # if outfile doesn't exist, no need to close it

            logger.info(f'Results for {len(results)} findings are written to {full_filename}')
    elif not results:
        logger.info(colored("No findings found!", "green"))
        return_value = 0
    else:
        logger.info(f"Complete list with {len(results)} failures is printed below:\n")
        print(json.dumps(results, indent=4))

    return return_value
