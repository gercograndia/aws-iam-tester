"""
Tests for the command module
"""
import os
import subprocess
import pytest
import pathlib

from pyassert import *

script_path = pathlib.Path(__file__).parent.absolute()

from aws_iam_tester import cli
def test_runas_module():
    exit_status = os.system(f'python -m aws_iam_tester --help')
    assert exit_status == 0

def test_help():
    process = subprocess.Popen(
        ['aws_iam_tester', '--help'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()
    assert_that(str(stdout)).contains('Usage')

def test_version():
    process = subprocess.Popen(
        ['aws_iam_tester', '--version'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()
    assert_that(str(stdout)).contains('version')

def test_test_runs():
    process = subprocess.Popen(
        ['aws_iam_tester', '--config-file', f'{script_path}/config.yml', '--number-of-runs', '10'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()

def test_dry_run():
    process = subprocess.Popen(
        ['aws_iam_tester', '--config-file', f'{script_path}/config.yml', '--dry-run'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()

def test_no_system_roles():
    process = subprocess.Popen(
        ['aws_iam_tester', '--config-file', f'{script_path}/config.yml', '--no-include-system-roles'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()

def test_full_run():
    output_dir = '/tmp/iam_tester_results'
    process = subprocess.Popen(
        ['aws_iam_tester', '--config-file', f'{script_path}/config.yml', '--write-to-file', '--output-location', output_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    assert_that(stderr).is_not_none()
    assert_that(str(stdout)).contains("are written to")
    assert_that(output_dir).is_a_directory()
