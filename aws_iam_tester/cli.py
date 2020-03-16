#! /usr/bin/env python3

import os
import sys
import errno
import json
import boto3
import botocore
import yaml
import click
import logging
import re
import time

from termcolor import colored
from botocore.config import Config

# Defaults
DEFAULT_SLEEP_SECONDS=60

logger = None

# define boto3 retry logic, as the simulation api might do some throttling
config = Config(
    retries = dict(
        max_attempts = 10
    )
)

@click.command()
@click.option('--number-of-runs', '-n', help='Run only a limited number of simulations, and then abort.', type=int, default=-1)
@click.option('--dry-run/--no-dry-run', '-dr/-ndr', help='Dry run mode will not run the actual policy simulations.', default=False)
@click.option('--config-file', '-c', help='Config file, default config.yml.', default='config.yml')
@click.option('--write-to-file/--no-write-to-file', '-w/-nw', help='Write results to file.', default=False)
@click.option('--debug/--no-debug', '-d/-nd', help='Print debug messages.', default=False)
def test_policies(number_of_runs, dry_run, config_file, write_to_file, debug):
    setup_logger(
        debug=debug,
        )

    # first get current account id
    client = boto3.client("sts")
    account_id = client.get_caller_identity()["Account"]

    config, global_exemptions, user_landing_account = read_config(config_file)

    logger.debug("dynamically collect users and roles")
    users = get_iam_users()
    roles = get_iam_roles(user_landing_account, account_id)

    sources = []
    sources.extend(users)
    sources.extend(roles)

    # # for testing
    # sources = [
    #     # "arn:aws:iam::325855013273:user/test-user-remove-after-20200401",
    #     "arn:aws:iam::325855013273:role/SHARED_PLATFORM_ENGINEER_ROLE",
    # ]

    results = []

    counter=0
    logger.debug("Start checking the configs")
    for c in config['tests']:
        # do we need to break?
        if number_of_runs > 0 and counter > number_of_runs:
            break

        actions = c["actions"]
        resources = [ x.format(account_id=account_id) for x in c["resources"] ]

        # create a full list of exemptions
        exemptions = []
        if "exemptions" in c:
            exemptions = c["exemptions"]
        exemptions.extend(global_exemptions)

        # check if the expected result has the expected values
        expected_result = c["expected_result"].lower()
        if expected_result not in ['fail', 'succeed']:
            raise ValueError(f"The expected result should be 'fail' or 'succeed'. It is now '{expected_result}'")

        expect_failures = (expected_result == "fail")
        logger.debug(f"Run config for actions: {actions} with resources {resources}")

        for source in sources:
            # check if the source is exempt from testing
            exempt = False
            for e in exemptions:
                if re.match(e, source):
                    exempt = True
                    logger.debug(f"\nSource {source} is exempt from testing using exemption: {e}")
                    break
            
            counter += 1
            if number_of_runs > 0 and counter > number_of_runs:
                print("\n")
                logger.debug("Test run mode activated, max iterations reached.")
                break
            elif dry_run:
                logger.debug(f"Dry run mode, no simulation for {source}")
            elif not exempt:
                evaluation_results = simulate_policy(
                    source=source,
                    actions=actions,
                    resources=resources,
                )

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
                        print(colored(f".", "green"), end="")
                        sys.stdout.flush()
                else:
                    r = construct_results(
                        source=source,
                        expect_failures=expect_failures,
                        results=failures,
                        print_results=debug,
                        )
                    results.extend(r)
                    if not debug:
                        print(colored(f".", "red"), end="")
                        sys.stdout.flush()

    handle_results(
        results=results,
        write_to_file=write_to_file,
        account_id=account_id,
    )

def setup_logger(debug):
    # set up the logger
    # logger = logging.basicConfig()
    global logger
    logger = logging.getLogger('iam-tester')
    logger.propagate = False
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        if debug:
            logger.setLevel(level=logging.DEBUG)
            ch.setLevel(level=logging.DEBUG)
        else:
            logger.setLevel(level=logging.INFO)
            ch.setLevel(level=logging.INFO)
        formatter = logging.Formatter(
            "%(levelname)s:\t%(message)s"
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)

def read_config(config_file):
    logger.debug(f"Read config file {config_file}")

    try:
        with open(config_file) as file:
            config = yaml.load(file, Loader=yaml.FullLoader)
    except IOError as ioe:
        logger.error(f"Config '{config_file}' not accessible")
        raise(ioe)
    finally:
        try:
            file.close()
        except Exception:
            pass

    global_exemptions = []
    if "global_exemptions" in config:
        global_exemptions = config["global_exemptions"]

    user_landing_account = None
    if "user_landing_account" in config:
        user_landing_account = config["user_landing_account"]

    return config, global_exemptions, user_landing_account

def get_iam_roles(user_landing_account, my_account):
    client = boto3.client('iam')
    roles = []
    paginator = client.get_paginator('list_roles')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        rolelist = page["Roles"]
        for role in rolelist:
            # only get the roles that can be assumed by 'users'
            policy_doc = json.dumps(role["AssumeRolePolicyDocument"])

            if 'service-role' not in role["Path"] and ( # ignore service roles
                f"arn:aws:iam::{my_account}:root" in policy_doc or # accept roles that can be assumed by users in my account
                f"arn:aws:iam::{user_landing_account}:root" in policy_doc or # accept roles that can be assumed by a dedicated user landing account
                f"arn:aws:iam::{my_account}:saml-provider" in policy_doc # accept roels that can be assumed with SAML
            ):
                roles.append(role['Arn'])
    
    return roles


def get_iam_users():
    client = boto3.client('iam')
    users = []
    paginator = client.get_paginator('list_users')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        userlist = page["Users"]
        for user in userlist:
            users.append(user['Arn'])
    
    return users


def simulate_policy(source, actions, resources):
    """Simulate a set of actions from a specific principal against a resource"""
    def simulate():
        client = boto3.client("iam", config=config)
        response = client.simulate_principal_policy(
            PolicySourceArn=source,
            ActionNames=actions,
            ResourceArns=resources,
            ContextEntries=[
                {
                    'ContextKeyName': 'aws:MultiFactorAuthPresent',
                    'ContextKeyValues': [
                        # Always test with MFA present, which is worst case scenario (as lots of rights might be revoked without MFA)
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
            ],
        )
        return response["EvaluationResults"]

    try:
        return simulate()
    except botocore.exceptions.ClientError as ce:
        if "throttling" in str(ce).lower():
            logger.warn(colored("Throttling of API is requested. Sleep for 60 seconds and try again"), "blue")
            time.sleep(DEFAULT_SLEEP_SECONDS)
            return simulate()
        else:
            raise(ce)


def is_denied(evaluationResults):
    return evaluationResults["EvalDecision"] != "allowed"


def construct_results(source, expect_failures, results, print_results=True):
    """Constructs a dict with the results of a simulation evaluation result"""
    output = ""
    response = []
    for er in results:
        message = (
            f"\nSource: {source}\n"
            f"Must fail: {expect_failures}\n"
            f"Evaluated Action Name: {er['EvalActionName']}\n"
            f"\tEvaluated Resource name: {er['EvalResourceName']}\n"
            f"\tDecision: {er['EvalDecision']}"
        )
        r = {
            "source": source,
            "action": er['EvalActionName'],
            "must_fail": expect_failures,
            "resource": er['EvalResourceName'],
            "decision": er['EvalDecision'],
        }
        response.append(r)
        output += message
    if print_results:
        print(colored(output, "red"))
    
    return response


def handle_results(results, write_to_file, account_id):
    print("\n\n")
    logger.debug("Handle results")
    if write_to_file:
        # first ensure directory exists
        try:
            path = f"{os.getcwd()}/results"
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise
        try:
            timestr = time.strftime("%Y%m%d-%H%M%S")
            filename = f'{path}/results-{account_id}-{timestr}.json' 
            with open(filename, 'w') as outfile:
                json.dump(results, outfile, indent=4)
            logger.info(f'Results for {len(results)} findings are written to {filename}')
        finally:
            outfile.close()
    else:
        logger.info(f"Complete list with {len(results)} failures is printed below:\n")
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    test_policies()
