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

from aws_iam_tester import __version__

# Defaults
DEFAULT_SLEEP_SECONDS=300

logger = None

# define boto3 retry logic, as the simulation api might do some throttling
boto3_config = Config(
    retries = dict(
        max_attempts = 10
    )
)

@click.command()
@click.option('--number-of-runs', '-n', help='Run only a limited number of simulations, and then abort.', type=int, default=-1)
@click.option('--dry-run/--no-dry-run', '-dr/-ndr', help='Dry run mode will not run the actual policy simulations. Default: False', default=False)
@click.option('--config-file', '-c', help='Config file location. Default: config.yml.', default='config.yml')
@click.option('--include-system-roles/--no-include-system-roles', '-sr/-nsr', help='Include non-user-assumable roles. Default: True', default=True)
@click.option('--write-to-file/--no-write-to-file', '-w/-nw', help='Write results to file. Default: False', default=False)
@click.option('--output-location', '-o', help='Output location, either s3 (start with s3://) or locally. Default: ./results', default='./results')
@click.option('--debug/--no-debug', '-d/-nd', help='Print debug messages. Default: False', default=False)
@click.version_option(version=__version__)
def main(number_of_runs, dry_run, config_file, include_system_roles, write_to_file, output_location, debug):
    setup_logger(
        debug=debug,
        )
    # first get current account id
    sts_client = boto3.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]

    # try to get the friendly account name
    iam_client = boto3.client("iam")
    try:
        account_alias = iam_client.list_account_aliases(MaxItems=1)["AccountAliases"][0]
    except:
        account_alias = account_id
    

    config, global_exemptions, user_landing_account = read_config(config_file)

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

    # for quick testing
    # sources = [
    #     "arn:aws:iam::351902532037:role/powerbi_gateway",
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

        # check if this test contain a 'limit_to' element
        limit_to = []
        if "limit_to" in c:
            limit_to = c["limit_to"]

        # check if the expected result has the expected values
        expected_result = c["expected_result"].lower()
        if expected_result not in ['fail', 'succeed']:
            raise ValueError(f"The expected result should be 'fail' or 'succeed'. It is now '{expected_result}'")

        expect_failures = (expected_result == "fail")
        logger.debug(f"Run config for actions: {actions} with resources {resources}")

        for source in sources:
            if limit_to: # do we have a limit_to?
                exempt = True
                for l in limit_to:
                    if re.match(l, source):
                        exempt = False
                        break

                if exempt and debug:
                    logger.debug(f"\nSource {source} is not included in whitelist")
                elif exempt:
                    print(colored(f".", "blue"), end="")
                    sys.stdout.flush()
            else: # or is this source exempt from testing
                exempt = False
                for e in exemptions:
                    if re.match(e, source):
                        exempt = True
                        if debug:
                            logger.debug(f"\nSource {source} is exempt from testing using exemption: {e}")
                        else:
                            print(colored(f".", "blue"), end="")
                            sys.stdout.flush()
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
        output_location=output_location,
        account=account_alias,
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

def get_iam_roles(user_landing_account, my_account, include_system_roles):
    client = boto3.client('iam')
    roles = []
    paginator = client.get_paginator('list_roles')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        rolelist = page["Roles"]
        for role in rolelist:
            # only get the roles that can be assumed by 'users'
            policy_doc = json.dumps(role["AssumeRolePolicyDocument"])

            if 'aws-service-role' not in role["Path"] and ( # ignore service roles
                f"arn:aws:iam::{my_account}:root" in policy_doc or # accept roles that can be assumed by users in my account
                f"arn:aws:iam::{user_landing_account}:root" in policy_doc or # accept roles that can be assumed by a dedicated user landing account
                f"arn:aws:iam::{my_account}:saml-provider" in policy_doc or # accept roles that can be assumed with SAML
                include_system_roles == True # do we want to include non user assumable roles
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

    client = boto3.client("iam", config=boto3_config)
    try:
        return simulate()
    except client.exceptions.NoSuchEntityException as nsee:
        logger.error(f"\nCould not find entity {source} during simulation, has it just been removed?\n{nsee}")
        # but ignore it
        pass
        return None
    except client.exceptions.ClientError as ce:
        if "throttling" in str(ce).lower():
            logger.error(colored(f"\nThrottling of API is requested. Sleep for {DEFAULT_SLEEP_SECONDS} seconds and try again\n"), "blue")
            time.sleep(DEFAULT_SLEEP_SECONDS)
            return simulate()
        else:
            raise(ce)
    except Exception as e:
        logger.error(f"\nError simulating entity {source}\n{e}")
        raise(e)

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


def handle_results(results, write_to_file, output_location, account):
    print("\n\n")
    logger.debug("Handle results")
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
            except IndexError as ie:
                prefix = ""
                pass
            
            try:
                full_filename = f'{prefix}/{filename}'
                logger.debug(f"Try to write results to s3://{bucket}/{full_filename}")
                s3_client = boto3.client('s3')
                s3_client.put_object(
                    Body=json.dumps(results).encode(),
                    Bucket=bucket,
                    Key=full_filename,
                )
            except Exception as e:
                logger.error(f"Could not write results to s3: {e}")
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
            except Exception as e:
                logger.error(f"Could not write results to file system: {e}")
            finally:
                outfile.close()

            logger.info(f'Results for {len(results)} findings are written to {full_filename}')
    elif not results:
        logger.info(colored("No findings found!", "green"))
    else:
        logger.info(f"Complete list with {len(results)} failures is printed below:\n")
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
