#!/usr/bin/env python

import codecs

from os import path
from setuptools import setup

install_requires = [
    'boto3',
    'pyyaml',
    'click',
    'termcolor',
]

version = "0.0.1"

setup(
    name='aws-iam-tester',
    version=version,
    description='AWS IAM tester - simple command-line tool to check '
                'permissions handed out to IAM users and roles',
    long_description=codecs.open(
        path.join(path.abspath(path.dirname(__file__)), 'README.md'),
        mode='r',
        encoding='utf-8'
    ).read(),
    long_description_content_type="text/markdown",
    url='https://github.com/gercograndia/aws-iam-tester',
    author='Gerco Grandia',
    author_email='gerco.grandia@4synergy.nl',
    maintainer='Gerco Grandia',
    keywords='aws iam tester',
    packages=['aws_iam_tester'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Python Software Foundation License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
    ],
    setup_requires=[
        'setuptools',
    ],
    install_requires=install_requires,
    entry_points={
        'console_scripts': ['aws_iam_tester=aws_iam_tester.cli:test_policies']
    },
    include_package_data=True,
)