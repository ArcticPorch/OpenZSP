"""
IAM effective-permission evaluation: identity and resource policies, explicit
deny, permission boundaries, SCPs, NotAction/NotResource, conditions -- at
action level, so a narrow deny never wipes a whole capability.
"""

from app.connectors.aws.policy import effective_capabilities, is_public, parse_policy
from app.models.capability import Capability as C

USER = "arn:aws:iam::111122223333:user/dana"
BUCKET = "arn:aws:s3:::payroll-exports"
ROOT = "arn:aws:iam::111122223333:root"


def policy(*statements, pid="p"):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)}, pid)


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def caps(*args, **kwargs):
    return {e.capability: e for e in effective_capabilities(USER, BUCKET, *args, **kwargs)}


def test_a_service_wildcard_is_admin():
    assert C.ADMIN in caps(policy(allow("s3:*")))


def test_read_only_is_read_only():
    got = caps(policy(allow(["s3:GetObject", "s3:ListBucket"], [BUCKET, BUCKET + "/*"])))
    assert set(got) == {C.READ}


def test_a_statement_on_the_objects_is_access_to_the_bucket():
    assert C.READ in caps(policy(allow("s3:GetObject", BUCKET + "/*")))


def test_other_resources_are_not_this_one():
    assert caps(policy(allow("s3:*", "arn:aws:s3:::someone-else/*"))) == {}


def test_a_narrow_deny_does_not_wipe_a_whole_capability():
    """Deny DeleteObject; DeleteBucket is still DESTROY -- and admin is gone."""
    got = caps(policy(allow("s3:*"), deny("s3:DeleteObject")))
    assert C.ADMIN not in got
    assert C.DESTROY in got and C.MANAGE_PERMISSION in got


def test_explicit_deny_of_everything_wins():
    assert caps(policy(allow("s3:*"), deny("*"))) == {}


def test_not_action_allows_everything_else():
    """Everything but s3:Delete*: every S3 action that destroys is excluded, the rest stays."""
    got = caps(policy({"Effect": "Allow", "NotAction": "s3:Delete*", "Resource": "*"}))
    assert C.DESTROY not in got and C.ADMIN not in got
    assert {C.READ, C.WRITE, C.MANAGE_PERMISSION} <= set(got)


def test_not_resource_excludes_the_named_resource():
    assert caps(policy({"Effect": "Allow", "Action": "s3:*", "NotResource": BUCKET + "*"})) == {}


def test_a_boundary_caps_identity_policies():
    got = caps(policy(allow("s3:*")), boundary=policy(allow("s3:Get*"), pid="boundary"))
    assert set(got) == {C.READ}


def test_every_scp_level_must_allow():
    root_level = policy(allow("*"), pid="FullAWSAccess")
    ou_level = policy(allow("s3:Get*"), pid="ReadOnlyOU")
    got = caps(policy(allow("s3:*")), scp_levels=[root_level, ou_level])
    assert set(got) == {C.READ}


def test_an_scp_deny_wins_over_any_allow():
    got = caps(policy(allow("s3:*")), scp_levels=[policy(allow("*"), deny("s3:PutBucketPolicy"))])
    assert C.ADMIN not in got and C.READ in got


def test_a_resource_policy_naming_the_principal_grants_directly():
    bucket_policy = policy({"Effect": "Allow", "Principal": {"AWS": USER},
                            "Action": "s3:GetObject", "Resource": BUCKET + "/*"}, pid="bucket")
    got = caps((), resource_statements=bucket_policy)
    assert set(got) == {C.READ} and got[C.READ].sources == ("bucket",)


def test_a_resource_policy_naming_the_account_root_delegates_to_iam():
    bucket_policy = policy({"Effect": "Allow", "Principal": {"AWS": ROOT},
                            "Action": "s3:*", "Resource": BUCKET + "/*"})
    assert caps((), resource_statements=bucket_policy) == {}


def test_conditional_allow_is_kept_and_marked():
    """Never assumed false: the grant stands, flagged with its condition keys."""
    got = caps(policy(allow("s3:GetObject", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})))
    assert got[C.READ].conditional
    assert got[C.READ].condition_keys == ("aws:MultiFactorAuthPresent",)


def test_conditional_deny_is_not_trusted_to_block():
    got = caps(policy(allow("s3:*"), deny("*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})))
    assert C.ADMIN in got


ROLE = "arn:aws:iam::111122223333:role/deploy"


def assumable(identity, trust):
    got = effective_capabilities(USER, ROLE, identity, resource_statements=trust, account_root=ROOT)
    return C.IMPERSONATE in {e.capability for e in got}


def trust(principal):
    return parse_policy({"Statement": [{"Effect": "Allow", "Principal": principal,
                                        "Action": "sts:AssumeRole"}]}, "trust")


def test_trusting_the_account_root_delegates_to_identity_policies():
    assert assumable(policy(allow("sts:AssumeRole", ROLE)), trust({"AWS": ROOT}))
    assert not assumable((), trust({"AWS": ROOT}))


def test_a_bare_account_id_in_trust_means_its_root():
    assert assumable(policy(allow("sts:AssumeRole", ROLE)), trust({"AWS": "111122223333"}))


def test_trusting_the_principal_directly_needs_no_identity_policy():
    assert assumable((), trust({"AWS": USER}))


def test_a_service_only_role_cannot_be_assumed_by_people():
    """sts:AssumeRole on * must not read as 'can become every role'."""
    assert not assumable(policy(allow("sts:AssumeRole")), trust({"Service": "lambda.amazonaws.com"}))


def test_a_public_bucket_policy_is_public():
    assert is_public(policy({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                             "Resource": BUCKET + "/*"}))
    assert not is_public(policy({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                 "Resource": BUCKET + "/*",
                                 "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}))
