"""
Tests for the command module
"""
import os
import subprocess
import pytest
import pathlib

from pyassert import assert_that
# from aws-iam-tester import cli

script_path = pathlib.Path(__file__).parent.absolute()

def run_command(command_list, do_assert=True, show_debug=False):
    process = subprocess.Popen(
        command_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    if show_debug:
        print(f"Return code: {process.returncode}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")

    if do_assert:
        assert_that(process.returncode).is_less_than(2)
        assert_that(stderr).is_not_none()

    return process.returncode, str(stdout), str(stderr)

def test_runas_module():
    exit_status = os.system(f'python -m aws_iam_tester --help')
    assert exit_status == 0

def test_help():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', '--help']
    )
    assert_that(stdout).contains('Usage')

def test_version():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', '--version'],
    )
    assert_that(stdout).contains('version')

def test_test_runs():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', '--config-file', f'{script_path}/config.yml', '--number-of-runs', '10'],
    )


def test_dry_run():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'account',  '--config-file', f'{script_path}/config.yml', '--dry-run'],
    )

def test_no_system_roles():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'account', '--config-file', f'{script_path}/config.yml', '--no-system-roles'],
    )

def test_full_run():
    output_dir = '/tmp/iam_tester_results'
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'account', '--config-file', f'{script_path}/config.yml', '--write-to-file', '--output-location', output_dir],
    )
    assert_that(stdout).contains("are written to")
    assert_that(output_dir).is_a_directory()

def test_full_run_with_global_limit():
    output_dir = '/tmp/iam_tester_results'
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'account', '--config-file', f'{script_path}/config_with_global_limit_to.yml', '--write-to-file', '--output-location', output_dir],
    )
    assert_that(stdout).matches(r"(^(.)*are written to(.)*$)|(^(.)*No findings found(.)*$)")
    
    assert_that(output_dir).is_a_directory()

def test_check_user_action():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'action', '-u', 'ggrandia', '-a', 'glue:DeleteTable'],
    )
    assert_that(stdout).matches(r"(^(.)*Action(.)*glue:DeleteTable(.)*$)")

def test_check_invalid_user_action():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'action', '-u', 'non_existent_user', '-a', 'glue:DeleteTable'],
        do_assert=False,
    )
    assert_that(stdout).matches(r"(^(.)*Could not find entity(.)*$)")
    assert_that(returncode).is_equal_to(2)

def test_check_role_action():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'action', '-r', 'api2s3_worker_role', '-a', 'glue:DeleteTable'],
    )
    assert_that(stdout).matches(r"(^(.)*Action(.)*glue:DeleteTable(.)*$)")

def test_check_invalid_user_action():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'action', '-r', 'non_existent_role', '-a', 'glue:DeleteTable'],
        do_assert=False,
    )
    assert_that(stdout).matches(r"(^(.)*Could not find entity(.)*$)")
    assert_that(returncode).is_equal_to(2)

def test_check_both_user_and_role_action():
    returncode, stdout, stderr = run_command(
        ['aws-iam-tester', 'action', '-u', 'whatever', '-r', 'whatever', '-a', 'glue:DeleteTable'],
        do_assert=False,
    )
    assert_that(stdout).matches(r"(^(.)*Pass in user or role, not both(.)*$)")
    assert_that(returncode).is_equal_to(2)

# Keep this method last to avoid disrupting other methods
def test_without_aws_creds():
    os.environ["AWS_ACCESS_KEY_ID"] = "whatever"
    os.environ["SECRET_AWS_ACCESS_KEY"] = "whatever"
    returncode, stdout, stderr = run_command(
        command_list=['aws-iam-tester', 'account', '--config-file', f'{script_path}/config.yml', '--dry-run'],
        do_assert=False
    )
    del os.environ["AWS_ACCESS_KEY_ID"]
    del os.environ["SECRET_AWS_ACCESS_KEY"]

    assert_that(returncode).is_equal_to(2)
    assert_that(stdout).matches(r"(^(.)*InvalidClientTokenId(.)*$)")
