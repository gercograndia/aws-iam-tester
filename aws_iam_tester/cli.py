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

from __future__ import annotations
import json

import sys
import click

from aws_iam_tester.lib import AwsIamTester

from typing import Dict, List, Tuple, Optional, Any
from termcolor import colored
from outdated import check_outdated # type: ignore

from . import __version__

class DefaultGroup(click.Group):
    '''
    Allow a default command for a group
    '''
    ignore_unknown_options = True

    def __init__(self, *args, **kwargs):
        default_command = kwargs.pop('default_command', None)
        super(DefaultGroup, self).__init__(*args, **kwargs)
        self.default_cmd_name = None
        if default_command is not None:
            self.set_default_command(default_command)

    def set_default_command(self, command):
        if isinstance(command, str):
            cmd_name = command
        else:
            cmd_name = command.name
            self.add_command(command)
        self.default_cmd_name = cmd_name

    def parse_args(self, ctx, args):
        if not args and self.default_cmd_name is not None:
            args.insert(0, self.default_cmd_name)
        return super(DefaultGroup, self).parse_args(ctx, args)

    def get_command(self, ctx, cmd_name):
        if cmd_name not in self.commands and self.default_cmd_name is not None:
            ctx.args0 = cmd_name
            cmd_name = self.default_cmd_name
        return super(DefaultGroup, self).get_command(ctx, cmd_name)

    def resolve_command(self, ctx, args):
        cmd_name, cmd, args = super(DefaultGroup, self).resolve_command(ctx, args)
        args0 = getattr(ctx, 'args0', None)
        if args0 is not None:
            args.insert(0, args0)
        return cmd_name, cmd, args

@click.group(cls=DefaultGroup, default_command="account")
def cli():
    pass

@cli.command(name="account")
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
    '--no-system-roles', '-N',
    help='Do not include non-user-assumable system roles.',
    is_flag=True,
    )
@click.option(
    '--write-to-file', '-w',
    help='Write results to file.',
    is_flag=True,
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
    )
@click.version_option(version=__version__)
def check_aws_account(
        number_of_runs: int,
        dry_run: bool,
        config_file: str,
        no_system_roles: bool,
        write_to_file: bool,
        output_location: str,
        debug: bool
    ) -> int:
    """
    Checks an entire AWS account based on the provided configuration.

    Based on the findings the following return values will be generated:
    0: Upon successful completion with NO findings
    1: Upon successful completion with findings
    2: Upon failures
    """

    check_latest_version()

    try:
        tester = AwsIamTester(debug=debug)
        result = tester.check_account(
            number_of_runs=number_of_runs,
            dry_run=dry_run,
            config_file=config_file,
            no_system_roles=no_system_roles,
            write_to_file=write_to_file,
            output_location=output_location,
        )
        sys.exit(result)
    except Exception as e:
        click.echo(f"Exception occured: {e}")
        if debug:
            raise
        sys.exit(2)

@cli.command(name="access")
@click.option(
    '--user', '-u',
    help='User name that will be validated, if user and role is omitted all entities having access will be returned',
    default=None,
    )
@click.option(
    '--role', '-r',
    help='Role name that will be validated, if user and role is omitted all entities having access will be returned',
    default=None,
    )
@click.option(
    '--action', '-a',
    help='Action that will be validated',
    )
@click.option(
    '--resource', '-R',
    help="Resource that will be validated, default '*'",
    default="*"
    )
@click.option(
    '--json-output', '-j',
    help="Output in json format",
    is_flag=True,
    default=False
    )
@click.option(
    '--debug', '-d',
    help='Print debug messages.',
    is_flag=True,
    default=False
    )
@click.version_option(version=__version__)
def check_access(
        user: str,
        role: str,
        action: str,
        resource: str,
        json_output: bool,
        debug: bool,
    ):
    """
    Checks whether the provided IAM identity has permissions on the provided actions and resource.

    Based on the findings the following return values will be generated:
    0: Upon successful completion and allowed
    1: Upon successful completion and not allowed
    2: Upon failures
    """

    check_latest_version()

    try:
        tester = AwsIamTester(debug=debug)
        if user or role:
            allowed = tester.check_action(
                user=user,
                role=role,
                action=action,
                resource=resource,
                json_output=json_output,
            )
        else:
            allowed = tester.check_access(
                action=action,
                resource=resource,
                json_output=json_output,
            )
            sys.exit(0 if allowed else 1)
        sys.exit(0 if allowed else 1)
    except Exception as e:
        click.echo(f"Exception occured: {e}")
        if debug:
            raise
        sys.exit(2)

@cli.command(name="search")
@click.option(
    '--action', '-a',
    help='Action that will be validated',
    required=True,
    )
@click.option(
    '--resource', '-R',
    help="Resource that will be validated, default '*'",
    default="*"
    )
@click.option(
    '--json-output', '-j',
    help="Output in json format",
    is_flag=True,
    default=False
    )
@click.option(
    '--debug', '-d',
    help='Print debug messages.',
    is_flag=True,
    default=False
    )
@click.version_option(version=__version__)
def search_access(
        action: str,
        resource: str,
        json_output: bool,
        debug: bool,
    ):
    """
    Search which users and roles have access on the provided actions and resource.

    Based on the findings the following return values will be generated:
    0: Upon successful completion and allowed
    1: Upon successful completion and not allowed
    2: Upon failures
    """

    check_latest_version()

    try:
        tester = AwsIamTester(debug=debug)
        allowed = tester.check_access(
            action=action,
            resource=resource,
            json_output=json_output,
        )
        sys.exit(0 if allowed else 1)
    except Exception as e:
        click.echo(f"Exception occured: {e}")
        if debug:
            raise
        sys.exit(2)

def check_latest_version():
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
