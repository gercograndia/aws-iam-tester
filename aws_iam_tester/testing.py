"""Test-only AWS client fakes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import botocore


class FakeNoSuchEntityException(Exception):
    pass


@dataclass
class FakePaginator:
    pages: List[Dict]

    def paginate(self):
        yield from self.pages


class FakeIAMExceptions:
    NoSuchEntityException = FakeNoSuchEntityException


class FakeSTSClient:
    def get_caller_identity(self):
        import os

        if os.getenv("AWS_ACCESS_KEY_ID") == "whatever" and os.getenv("SECRET_AWS_ACCESS_KEY") == "whatever":
            raise botocore.exceptions.ClientError(
                error_response={
                    "Error": {
                        "Code": "InvalidClientTokenId",
                        "Message": "The security token included in the request is invalid",
                    }
                },
                operation_name="GetCallerIdentity",
            )
        return {"Account": "208912673223"}


class FakeS3Client:
    def put_object(self, **kwargs):
        return {"ETag": '"fake"'}


class FakeIAMClient:
    exceptions = FakeIAMExceptions()

    def __init__(self):
        self._users = [
            {"Arn": "arn:aws:iam::208912673223:user/ggrandia"},
            {"Arn": "arn:aws:iam::208912673223:user/testADMINuser"},
            {"Arn": "arn:aws:iam::458445708552:user/iam_tester_user"},
        ]
        self._roles = [
            {
                "Arn": "arn:aws:iam::208912673223:role/api2s3_worker_role",
                "Path": "/",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Principal": {"AWS": "arn:aws:iam::208912673223:root"}}]
                },
            },
            {
                "Arn": "arn:aws:iam::208912673223:role/testADMINrole",
                "Path": "/",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Principal": {"AWS": "arn:aws:iam::208912673223:root"}}]
                },
            },
            {
                "Arn": "arn:aws:iam::458445708552:role/UNITTESTS-GLUE-WORKER-ROLE",
                "Path": "/",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Principal": {"AWS": "arn:aws:iam::458445708552:root"}}]
                },
            },
        ]

    def list_account_aliases(self, MaxItems=1):
        return {"AccountAliases": ["aws-iam-tester"]}

    def get_paginator(self, name):
        if name == "list_users":
            return FakePaginator([{"Users": self._users}])
        if name == "list_roles":
            return FakePaginator([{"Roles": self._roles}])
        raise ValueError(f"Unknown paginator: {name}")

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns, ContextEntries):
        if "non_existent_user" in PolicySourceArn or "non_existent_role" in PolicySourceArn:
            raise self.exceptions.NoSuchEntityException(PolicySourceArn)

        allowed = self._is_allowed(ContextEntries)
        decision = "allowed" if allowed else "explicitDeny"
        matched_statements = self._matched_statements() if allowed else self._matched_statements()

        results = []
        for action in ActionNames:
            for resource in ResourceArns:
                results.append(
                    {
                        "EvalActionName": action,
                        "EvalResourceName": resource,
                        "EvalDecision": decision,
                        "PermissionsBoundaryDecisionDetail": {
                            "AllowedByPermissionsBoundary": allowed,
                        },
                        "OrganizationsDecisionDetail": {
                            "AllowedByOrganizations": allowed,
                        },
                        "MatchedStatements": matched_statements,
                    }
                )

        return {"EvaluationResults": results}

    def _is_allowed(self, context_entries: Optional[List[Dict]]) -> bool:
        if not context_entries:
            return True

        for entry in context_entries:
            if entry.get("ContextKeyName") != "aws:MultiFactorAuthPresent":
                continue

            values = entry.get("ContextKeyValues", [])
            if isinstance(values, list) and any(str(value).lower() == "false" for value in values):
                return False
            return True

        return True

    def _matched_statements(self):
        return [
            {
                "SourcePolicyId": "admin_permissions",
                "SourcePolicyType": "IAM Policy",
                "StartPosition": {"Line": 3, "Column": 17},
                "EndPosition": {"Line": 8, "Column": 6},
            }
        ]


def create_test_clients():
    return FakeSTSClient(), FakeIAMClient(), FakeS3Client()
