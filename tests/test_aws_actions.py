"""
AWS actions -> capabilities: AWS's own access levels, plus documented overrides
where the level understates the harm.
"""

import pytest

from app.connectors.aws.actions import (
    OVERRIDES,
    action_levels,
    capabilities_of_pattern,
    capability_of_action,
)
from app.models.capability import Capability as C


def test_the_table_covers_aws():
    levels = action_levels()
    assert len(levels) >= 400
    assert sum(len(a) for a in levels.values()) >= 20000


def test_every_override_names_an_action_aws_lists():
    """A typo in an override is a silently dead line; this keeps them honest."""
    levels = action_levels()
    missing = sorted(k for k in OVERRIDES if k.split(":")[1] not in levels.get(k.split(":")[0], {}))
    assert missing == []


@pytest.mark.parametrize("action, capability", [
    ("s3:GetObject", C.READ),
    ("s3:ListBucket", C.READ),
    ("s3:PutObject", C.WRITE),
    ("s3:DeleteObject", C.DESTROY),
    ("ec2:TerminateInstances", C.DESTROY),
    ("iam:AttachRolePolicy", C.MANAGE_PERMISSION),
    ("s3:PutBucketPolicy", C.MANAGE_PERMISSION),
    ("iam:TagRole", C.WRITE),
    ("sts:AssumeRole", C.IMPERSONATE),
    ("iam:PassRole", C.IMPERSONATE),
    ("iam:CreateAccessKey", C.MANAGE_IDENTITY),
    ("cloudtrail:StopLogging", C.MANAGE_SECURITY_CONTROL),
    ("lambda:UpdateFunctionCode", C.DEPLOY),
    ("kms:Decrypt", C.READ),
    ("acme:Frobnicate", C.UNKNOWN),  # never defaulted to READ
])
def test_capability_of_action(action, capability):
    assert capability_of_action(action) is capability


@pytest.mark.parametrize("pattern, expected", [
    ("*", {C.ADMIN}),
    ("s3:*", {C.ADMIN}),
    ("s3:Get*", {C.READ}),
    ("ec2:Describe*", {C.READ}),
    ("s3:*Object", {C.READ, C.WRITE, C.DESTROY}),
])
def test_patterns_expand_against_the_table(pattern, expected):
    assert capabilities_of_pattern(pattern) == frozenset(expected)


def test_a_pattern_matching_nothing_falls_back_then_admits_ignorance():
    assert capabilities_of_pattern("acme:Get*") == frozenset({C.READ})
    assert capabilities_of_pattern("acme:Frob*") == frozenset({C.UNKNOWN})
