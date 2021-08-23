"""
The AwsIamTester class implements all necessary logic to run validations on an account, role or user.
"""

# pylint: disable=broad-except,C0103,E0401,R0912,R0913,R0914,R0915,R1702,W0603,W1203

from __future__ import annotations

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

from tabulate import tabulate
from typing import Any, Dict, List, Optional, Tuple, Union  #, Literal # Literal is p3.8 and higher
from termcolor import colored

class AwsIamTester():
    # Defaults
    DEFAULT_SLEEP_SECONDS = 300

    logger: logging.Logger
    logger_initialized: bool

    # define boto3 retry logic, as the simulation api might do some throttling
    boto3_config = botocore.config.Config(
        retries=dict(
            max_attempts=10
        )
    )

    def __init__(
        self,
        debug: bool,
        ):

        self.logger_initialized = False
        self.debug = debug

    def get_aws_data(self):
        logger = self.get_logger()

        account_id = None
        account_alias = None

        # first get current account id
        sts_client = boto3.client("sts")
        account_id = sts_client.get_caller_identity()["Account"]

        # try to get the friendly account name
        iam_client = boto3.client("iam")
        try:
            account_alias = iam_client.list_account_aliases(MaxItems=1)["AccountAliases"][0]
        except (KeyError, IndexError):
            account_alias = account_id
        
        return account_id, account_alias

    def check_action(
        self,
        user: str,
        role: str,
        action: str,
        resource: str,
        json_output: bool,
    ):
        "Checks whether a given user OR role has access to a particular action and resource"
        try:
            # logger = self.get_logger()
            account_id, account_alias = self.get_aws_data()

            if user and role:
                raise Exception("Pass in user or role, not both")
            elif user:
                source = f"arn:aws:iam::{account_id}:user/{user}"
            elif role:
                source = f"arn:aws:iam::{account_id}:role/{role}"
            else:
                raise Exception("One of user or role is required")

            results, counter = self.evaluate_sources(
                sources=[source],
                limit_to=[],
                exemptions=[],
                expect_failures=None, # this will then both denied and allows
                actions=[action],
                resources=[resource],
                sim_context=[],
            )
            if json_output:
                return self.handle_results(
                    results=results,
                )
            else:
                result = results[0]

                decision = result['decision']
                if decision == "allowed":
                    allowed = True
                    colour = "green"
                else:
                    allowed = False
                    colour = "red"

                pb = result['permissions_boundary']
                if pb == "allowed":
                    pb_colour = "green"
                elif pb == "denied":
                    pb_colour = "red"
                else:
                    pb_colour = "white"

                org_scp = result['org_scp']
                if org_scp == "allowed":
                    org_colour = "green"
                elif org_scp == "denied":
                    org_colour = "red"
                else:
                    org_colour = "white"

                click.secho(f"\n\nTest:", bold=True)
                click.echo(f"Source:\t\t\t{source}")
                click.echo(f"Action:\t\t\t{action}")
                click.echo(f"Resource:\t\t{resource}")
                click.secho(f"Result:\t\t\t", nl=False)
                click.secho(f"{decision}", fg=colour)
                click.secho(f"Permissions boundary:\t", nl=False)
                click.secho(f"{pb}", fg=pb_colour)
                click.secho(f"Allowed by org:\t\t", nl=False)
                click.secho(f"{org_scp}\n", fg=org_colour)

                ms_key = "matched_statements"
                if ms_key in result:
                    matched_statements = result[ms_key]

                    click.secho("Matched statements:", bold=True)
                    for ms in matched_statements:
                        click.echo(f"Policy:     {ms['SourcePolicyId']}")
                        click.echo(f"Type:       {ms['SourcePolicyType']}")
                        click.echo(f"Start:      L{ms['StartPosition']['Line']}:C{ms['StartPosition']['Column']}")
                        click.echo(f"End:        L{ms['EndPosition']['Line']}:C{ms['EndPosition']['Column']}")
                
                return allowed
        except botocore.exceptions.ClientError as ce:
            if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                click.echo(f"Please make sure you are logged in into AWS, with sufficient permissions.")

            raise

    def check_access(
        self,
        action: str,
        resource: str,
        json_output: bool,
    ):
        try:
            logger = self.get_logger()
            account_id, account_alias = self.get_aws_data()

            sources = self.determine_source(
                account_id=account_id,
                no_system_roles=False,
            )
            results, counter = self.evaluate_sources(
                sources=sources,
                limit_to=[],
                exemptions=[],
                expect_failures=True, # this will then return people with access
                actions=[action],
                resources=[resource],
                sim_context=[],
            )

            if json_output:
                return self.handle_results(
                    results=results,
                )
            else:
                to_print = []
                for r in results:
                    policies = ""
                    ms_key = "matched_statements"
                    if ms_key in r:
                        matched_statements = r[ms_key]

                        for ms in matched_statements:
                            policies = policies + ", " + ms['SourcePolicyId']

                        policies = policies[2:] # remove the first ', '

                    to_print.append([
                        r['source'],
                        r['action'],
                        r['resource'],
                        r['decision'],
                        policies,
                    ])

                self.show_summary(to_print)

        except botocore.exceptions.ClientError as ce:
            if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                click.echo(f"Please make sure you are logged in into AWS, with sufficient permissions.")

            raise

    def check_account(
        self, 
        number_of_runs: int,
        dry_run: bool,
        config_file: str,
        no_system_roles: bool,
        write_to_file: bool,
        output_location: str,
    ) -> int:
        """
        Run the IAM policy tests. It returns a dict with findings (or empty if none)
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

        try:
            logger = self.get_logger()
            account_id, account_alias = self.get_aws_data()

            config, global_exemptions, global_limit_to, user_landing_account = self.read_config(config_file)

            sources = self.determine_source(
                user_landing_account=user_landing_account,
                account_id=account_id,
                no_system_roles=no_system_roles,
                global_limit_to=global_limit_to,
                global_exemptions=global_exemptions,
            )
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

                source_results, counter = self.evaluate_sources(
                    sources=sources,
                    limit_to=limit_to,
                    exemptions=exemptions,
                    number_of_runs=number_of_runs,
                    dry_run=dry_run,
                    expect_failures=expect_failures,
                    counter=counter,
                    actions=actions,
                    resources=resources,
                    sim_context=sim_context,
                )
                results.extend(source_results)

            return self.handle_results(
                results=results,
                write_to_file=write_to_file,
                output_location=output_location,
                account=account_alias,
            )
        except botocore.exceptions.ClientError as ce:
            if re.match("^(.*)(security token|AccessDenied)(.*)$", str(ce)):
                click.echo(f"Please make sure you are logged in into AWS, with sufficient permissions.")

            raise

    def get_logger(self) -> logging.Logger:
        "Set up the logger (if not done yet) and returns it"
        if not self.logger_initialized:            
            self.logger = logging.getLogger('iam-tester')
            self.logger.propagate = False
            if not self.logger.handlers:
                ch = logging.StreamHandler(sys.stdout)
                if self.debug:
                    self.logger.setLevel(level=logging.DEBUG)
                    ch.setLevel(level=logging.DEBUG)
                else:
                    self.logger.setLevel(level=logging.INFO)
                    ch.setLevel(level=logging.INFO)
                formatter = logging.Formatter(
                    "%(levelname)s:\t%(message)s"
                )
                ch.setFormatter(formatter)
                self.logger.addHandler(ch)

        return self.logger

    def read_config(self, config_file: str) -> Tuple[Dict, List[str], List[str], Optional[str]]:
        "Read and parse config file"
        logger = self.get_logger()
        logger.debug(f"Read config file {config_file}")

        file = None
        try:
            with open(config_file) as file:
                config = yaml.load(file, Loader=yaml.FullLoader)
        except IOError:
            logger.error(f"Config '{config_file}' not accessible")
            raise
        finally:
            try:
                if file:
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
            self,
            user_landing_account: Optional[str],
            my_account: str,
            no_system_roles: bool
        ) -> List[str]:
        "Read (and filter) the IAM roles in the account"
        logger = self.get_logger()
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
                        # accept roles that can be assumed by users in my account
                        f"arn:aws:iam::{my_account}:root" in policy_doc or
                        # accept roles that can be assumed by a dedicated user landing account
                        f"arn:aws:iam::{user_landing_account}:root" in policy_doc or
                        # accept roles that can be assumed with SAML
                        f"arn:aws:iam::{my_account}:saml-provider" in policy_doc or
                        # do we want to include non user assumable roles
                        not no_system_roles
                    ):
                    roles.append(role['Arn'])

        return roles

    def get_iam_users(self) -> List[str]:
        "Get all IAM users"
        client = boto3.client('iam')
        users = []

        paginator = client.get_paginator('list_users')
        page_iterator = paginator.paginate()
        for page in page_iterator:
            userlist = page["Users"]
            for user in userlist:
                users.append(user['Arn'])

        return users

    def determine_source(
            self,
            account_id: str,
            user_landing_account: Optional[str] = None,
            no_system_roles: bool = False,
            global_limit_to: List[str] = [],
            global_exemptions: List[str] = [],
        ) -> List[str]:
        "Determine the list of sources that needs to be evaluated"
        logger = self.get_logger()

        logger.debug("dynamically collect users and roles")
        users = self.get_iam_users()
        roles = self.get_iam_roles(
            user_landing_account=user_landing_account,
            my_account=account_id,
            no_system_roles=no_system_roles
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
            logger.debug(f"Number of sources reduced with exemptions from {len_1} to {len(sources)}")

        return sources

    def evaluate_sources(
        self,
        sources: List[str],
        limit_to: List[str],
        exemptions: List[str],
        expect_failures: Optional[int],  # This is better but from p3.8 only: Optional[Union[Literal[True], Literal[False]]],
        actions: List[str],
        resources: List[str],
        sim_context: List[Dict[Any, Any]],
        number_of_runs: int = -1,
        dry_run: bool = False,
        counter: int = 0,
        ) -> Tuple[List[Dict], int]:
        "Evaluate the list of sources for a given configuration"

        logger = self.get_logger()
        logger.debug(f"Evaluate sources: {sources}")

        results = []
        for source in sources:
            if limit_to: # do we have a limit_to?
                exempt = True
                for limit in limit_to:
                    if re.match(limit, source):
                        exempt = False
                        break

                if exempt and self.debug:
                    logger.debug(f"\nSource {source} is not included in whitelist")
                elif exempt:
                    click.secho(".", fg="blue", nl=False)
                    sys.stdout.flush()
            else: # or is this source exempt from testing
                exempt = False
                for exemption in exemptions:
                    if re.match(exemption, source):
                        exempt = True
                        if self.debug:
                            logger.debug(
                                f"\nSource {source} is exempt from testing using: {exempt}"
                            )
                        else:
                            click.secho(".", fg="blue", nl=False)
                            sys.stdout.flush()
                        break

            counter += 1
            if 0 < number_of_runs < counter:
                click.echo("\n")
                logger.debug("Test run mode activated, max iterations reached.")
                break
            if dry_run:
                logger.debug(f"Dry run mode, no simulation for {source}")
            elif not exempt:
                evaluation_results = self.simulate_policy(
                    source=source,
                    actions=actions,
                    resources=resources,
                    sim_context=sim_context,
                )

                if evaluation_results:
                    denies = [x for x in evaluation_results if self.is_denied(x)]
                    allows = [x for x in evaluation_results if not self.is_denied(x)]

                    if expect_failures is None:
                        # just use all results
                        filtered_results = evaluation_results
                    elif expect_failures:
                        # allows are failures
                        filtered_results = allows
                    else:
                        # denies are failures
                        filtered_results = denies

                    success = (len(filtered_results) == 0)

                    if expect_failures is None:
                        results.extend(
                            self.construct_results(
                                source=source,
                                results=filtered_results,
                                print_results=self.debug,
                            )
                        )
                        if not self.debug:
                            if filtered_results[0]["EvalDecision"] == "allowed":
                                fg = "green"
                            else:
                                fg = "red"

                            click.secho(".", fg=fg, nl=False)
                            sys.stdout.flush()
                    elif success:
                        if self.debug:
                            click.secho(f"Success: {source}", fg="green")
                        else:
                            click.secho(".", fg="green", nl=False)
                            sys.stdout.flush()
                    else:
                        results.extend(
                            self.construct_results(
                                source=source,
                                results=filtered_results,
                                print_results=self.debug,
                            )
                        )

                        if not self.debug:
                            click.secho(".", fg="red", nl=False)
                            sys.stdout.flush()

        return results, counter

    def simulate_policy(
            self,
            source: str,
            actions: List[str],
            resources: List[str],
            sim_context: List[Dict] = None,
            ) -> List[Dict]:
        """Simulate a set of actions from a specific principal against a resource"""
        def simulate(
                source: str,
                actions: List[str],
                resources: List[str],
                sim_context: List[Dict] = None,
            ) -> List[Dict]:
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

        logger = self.get_logger()

        client = boto3.client("iam", config=self.boto3_config)
        try:
            return simulate(source, actions, resources, sim_context)
        except client.exceptions.NoSuchEntityException as nsee:
            click.echo("\n")
            logger.error(
                f"Could not find entity {source} during simulation, has it just been removed?\n{nsee}"
            )
            # but ignore it
            return []
        except client.exceptions.ClientError as ce:
            if "throttling" in str(ce).lower():
                logger.error(
                    colored(
                        "\nThrottling of API is requested. " +
                        f"Sleep for {self.DEFAULT_SLEEP_SECONDS} seconds and try again\n"
                    ),
                    "blue"
                )
                time.sleep(self.DEFAULT_SLEEP_SECONDS)
                return simulate(source, actions, resources, sim_context)
            else:
                raise

    def is_denied(self, evaluationResults: Dict) -> bool:
        "Returns whether or not the evaluation is denied"
        return evaluationResults["EvalDecision"] != "allowed"

    def construct_results(
            self,
            source: str,
            results: Any,
            print_results: bool = True,
        ) -> List[Dict]:
        """Constructs a dict with the results of a simulation evaluation result"""
        output = ""
        response = []

        for er in results:
            if er.get("PermissionsBoundaryDecisionDetail", None):
                if er.get("PermissionsBoundaryDecisionDetail").get("AllowedByPermissionsBoundary"):
                    pb = "allowed"
                else:
                    pb = "denied"
            else:
                pb = "no_pb"

            if er.get("OrganizationsDecisionDetail", None):
                if er.get("OrganizationsDecisionDetail").get("AllowedByOrganizations"):
                    org_scp = "allowed"
                else:
                    org_scp = "denied"
            else:
                org_scp = "no_org"

            message = (
                f"\nSource: {source}\n"
                f"Evaluated Action Name: {er['EvalActionName']}\n"
                f"\tEvaluated Resource name: {er['EvalResourceName']}\n"
                f"\tDecision: {er['EvalDecision']}\n"
                f"\Permissions boundary: {pb}\n"
                f"\tOrganizations policy: {org_scp}\n"
                f"\tMatched statements: {er['MatchedStatements']}"
            )
            r = {
                "source": source,
                "action": er['EvalActionName'],
                "resource": er['EvalResourceName'],
                "decision": er['EvalDecision'],
                "permissions_boundary": pb,
                "org_scp": org_scp,
                "matched_statements": er['MatchedStatements'],
            }
            response.append(r)
            output += message
        if print_results:
            click.secho(output, fg="red")

        return response

    def handle_results(
            self,
            results: List[Dict],
            write_to_file: bool = False,
            output_location: str = "",
            account: str = "",
        ) -> int:
        "Print the results or write them to file"
        logger = self.get_logger()

        click.echo("\n\n")
        logger.debug("Handle results")
        return_value = 1
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

                full_filename = f'{prefix}/{filename}'
                logger.debug(f"Try to write results to s3://{bucket}/{full_filename}")
                s3_client.put_object(
                    Body=json.dumps(results).encode(),
                    Bucket=bucket,
                    Key=full_filename,
                )
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
                outfile = None
                try:
                    full_filename = f'{path}/{filename}'
                    logger.debug(f"Try to write results to local file system: {full_filename}")
                    with open(full_filename, 'w') as outfile:
                        json.dump(results, outfile, indent=4)
                except IOError as e:
                    logger.error(f"Could not write results to file system: {e}")
                finally:
                    try:
                        if outfile:
                            outfile.close()
                    except:
                        pass # if outfile doesn't exist, no need to close it

                logger.info(f'Results for {len(results)} results are written to {full_filename}')
        elif not results:
            logger.info(colored("No findings found!", "green"))
            return_value = 0
        else:
            logger.info(f"Complete list with {len(results)} results is printed below:\n")
            click.echo(json.dumps(results, indent=4))

        return return_value

    def show_summary(self, results):
        '''
        Show summary containing test results.
        '''
        click.secho("\n\nSummary:\n", bold=True)
        headers = [
            'Source',
            'Action',
            'Resource',
            'Decision',
            'Policies',
        ]

        click.echo(tabulate(results, headers=headers, tablefmt="github"))
        click.echo("\n")

