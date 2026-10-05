"""
Generate examples/aws_sample_account/: a small, realistic AWS account export in
the exact shapes the AWS CLI produces, for demos and end-to-end tests.

    ./venv/Scripts/python.exe tools/make_aws_sample.py

Deterministic: fixed account, fixed export time, no randomness. Every planted
situation is real IAM mechanics, not a label -- the engine has to find it:

  ci-deployer    service user with AdministratorAccess; people sign in with it
  alice          analytics read + AssumeRole on DataEngineerRole (s3:* on the
                 CRITICAL payments ledger): an attack path
  eve            external contractor; group may assume SupportRole (DynamoDB on
                 the CRITICAL customers table); failed-login burst, then 120
                 scans through the role within the hour
  bob            iam:* capped by a read-only permission boundary; cloudtrail:*
                 whose tamper actions an SCP denies -- for AdministratorAccess
                 holders too, on the org trail
  carol          s3:* on the payments ledger, only with MFA (conditional)
  svc-reporting  secretsmanager:GetSecretValue on every secret
  breakglass     AdministratorAccess, tagged break-glass, never used
  old-intern     read on marketing assets, no activity in the trail
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "examples" / "aws_sample_account"
ACCOUNT = "111122223333"
EXPORTED = datetime(2026, 10, 1, tzinfo=timezone.utc)
REGION = "us-east-1"


def arn_user(name):
    return f"arn:aws:iam::{ACCOUNT}:user/{name}"


def arn_role(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def arn_policy(name):
    return f"arn:aws:iam::{ACCOUNT}:policy/{name}"


LEDGER = "arn:aws:s3:::acme-payments-ledger"
LAKE = "arn:aws:s3:::acme-analytics-lake"
MARKETING = "arn:aws:s3:::acme-marketing-assets"
CUSTOMERS = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/customers"
DB_SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/db-password-AbCdEf"
STRIPE_SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/stripe-key-XyZ123"
PAYMENTS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1111aaaa-2222-bbbb-3333-cccc4444dddd"
PAYMENTS_FN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:payments-api"
ORG_TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def tags(**kv):
    return [{"Key": k.replace("_", ":", 1).replace("_", "-"), "Value": v} for k, v in kv.items()]


def trust_root():
    return doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "sts:AssumeRole"})


def managed(name, document, arn=None):
    return {"PolicyName": name, "Arn": arn or arn_policy(name), "DefaultVersionId": "v1",
            "PolicyVersionList": [{"Document": document, "VersionId": "v1", "IsDefaultVersion": True}]}


ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
BOUNDARY = arn_policy("ReadOnlyBoundary")

authorization_details = {
    "Policies": [
        managed("AdministratorAccess", doc(allow("*")), ADMIN),
        managed("ReadOnlyBoundary", doc(allow(["iam:Get*", "iam:List*", "cloudtrail:*",
                                                "s3:Get*", "s3:List*"]))),
    ],
    "GroupDetailList": [{
        "GroupName": "Contractors", "Arn": f"arn:aws:iam::{ACCOUNT}:group/Contractors",
        "AttachedManagedPolicies": [],
        "GroupPolicyList": [{"PolicyName": "AssumeSupport",
                             "PolicyDocument": doc(allow("sts:AssumeRole", arn_role("SupportRole")))}],
    }],
    "UserDetailList": [
        {"UserName": "ci-deployer", "Arn": arn_user("ci-deployer"), "GroupList": [],
         "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN}],
         "UserPolicyList": [],
         "Tags": tags(zsp_identity_type="service", zsp_department="Platform")},
        {"UserName": "alice", "Arn": arn_user("alice"), "GroupList": [],
         "AttachedManagedPolicies": [],
         "UserPolicyList": [{"PolicyName": "AnalyticsAccess", "PolicyDocument": doc(
             allow(["s3:GetObject", "s3:ListBucket"], [LAKE, LAKE + "/*"]),
             allow("sts:AssumeRole", arn_role("DataEngineerRole")))}],
         "Tags": tags(zsp_department="Data Analytics", zsp_org_path="Data/Analytics")},
        {"UserName": "eve", "Arn": arn_user("eve"), "GroupList": ["Contractors"],
         "AttachedManagedPolicies": [], "UserPolicyList": [],
         "Tags": tags(zsp_department="Outsourced Support", zsp_external="true")},
        {"UserName": "bob", "Arn": arn_user("bob"), "GroupList": [],
         "AttachedManagedPolicies": [],
         "UserPolicyList": [{"PolicyName": "PlatformAdmin", "PolicyDocument": doc(
             allow("iam:*"), allow("cloudtrail:*"))}],
         "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": BOUNDARY},
         "Tags": tags(zsp_department="Platform", zsp_org_path="Engineering/Platform")},
        {"UserName": "carol", "Arn": arn_user("carol"), "GroupList": [],
         "AttachedManagedPolicies": [],
         "UserPolicyList": [{"PolicyName": "LedgerWithMFA", "PolicyDocument": doc(allow(
             "s3:*", [LEDGER, LEDGER + "/*"],
             Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))}],
         "Tags": tags(zsp_department="Finance", zsp_org_path="Finance/Treasury")},
        {"UserName": "svc-reporting", "Arn": arn_user("svc-reporting"), "GroupList": [],
         "AttachedManagedPolicies": [],
         "UserPolicyList": [{"PolicyName": "ReadSecrets", "PolicyDocument": doc(
             allow("secretsmanager:GetSecretValue"))}],
         "Tags": tags(zsp_identity_type="service", zsp_department="Finance")},
        {"UserName": "breakglass", "Arn": arn_user("breakglass"), "GroupList": [],
         "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN}],
         "UserPolicyList": [],
         "Tags": tags(zsp_break_glass="true", zsp_department="Security")},
        {"UserName": "old-intern", "Arn": arn_user("old-intern"), "GroupList": [],
         "AttachedManagedPolicies": [],
         "UserPolicyList": [{"PolicyName": "MarketingRead", "PolicyDocument": doc(
             allow(["s3:GetObject", "s3:ListBucket"], [MARKETING, MARKETING + "/*"]))}],
         "Tags": tags(zsp_department="Marketing")},
    ],
    "RoleDetailList": [
        {"RoleName": "DataEngineerRole", "Arn": arn_role("DataEngineerRole"),
         "AssumeRolePolicyDocument": trust_root(), "AttachedManagedPolicies": [],
         "RolePolicyList": [{"PolicyName": "LedgerAccess",
                             "PolicyDocument": doc(allow("s3:*", [LEDGER, LEDGER + "/*"]))}],
         "Tags": []},
        {"RoleName": "SupportRole", "Arn": arn_role("SupportRole"),
         "AssumeRolePolicyDocument": trust_root(), "AttachedManagedPolicies": [],
         "RolePolicyList": [{"PolicyName": "CustomersTable",
                             "PolicyDocument": doc(allow("dynamodb:*", CUSTOMERS))}],
         "Tags": []},
        {"RoleName": "LambdaExecRole", "Arn": arn_role("LambdaExecRole"),
         "AssumeRolePolicyDocument": doc({"Effect": "Allow",
                                          "Principal": {"Service": "lambda.amazonaws.com"},
                                          "Action": "sts:AssumeRole"}),
         "AttachedManagedPolicies": [],
         "RolePolicyList": [{"PolicyName": "WriteLake",
                             "PolicyDocument": doc(allow("s3:PutObject", LAKE + "/*"))}],
         "Tags": []},
    ],
}

scps = [
    {"level": "root", "policies": [{"PolicyId": "p-FullAWSAccess", "Name": "FullAWSAccess",
                                    "Content": json.dumps(doc(allow("*")))}]},
    {"level": "ou-workloads", "policies": [{"PolicyId": "p-protect-trail", "Name": "ProtectAuditTrail",
                                            "Content": json.dumps(doc(
                                                allow("*"),
                                                {"Effect": "Deny", "Action": [
                                                    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
                                                    "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
                                                 "Resource": "*"}))}]},
]

resources = {"ResourceTagMappingList": [
    {"ResourceARN": LEDGER, "Tags": tags(zsp_sensitivity="critical", Name="payments-ledger")},
    {"ResourceARN": LAKE, "Tags": tags(zsp_sensitivity="medium", Name="analytics-lake")},
    {"ResourceARN": MARKETING, "Tags": tags(zsp_sensitivity="low", Name="marketing-assets")},
    {"ResourceARN": CUSTOMERS, "Tags": tags(zsp_sensitivity="critical", Name="customers")},
    {"ResourceARN": DB_SECRET, "Tags": []},
    {"ResourceARN": STRIPE_SECRET, "Tags": []},
    {"ResourceARN": PAYMENTS_KEY, "Tags": tags(zsp_sensitivity="critical", Name="payments-key")},
    {"ResourceARN": PAYMENTS_FN, "Tags": tags(zsp_sensitivity="medium", Name="payments-api")},
    {"ResourceARN": ORG_TRAIL, "Tags": tags(zsp_sensitivity="critical", Name="org-trail")},
]}

resource_policies = {
    MARKETING: doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                    "Resource": MARKETING + "/*"}),
}

records = []


def event(when, user, source, name, *, resource=None, params=None, key="ASIA", error=None,
          role=None, source_identity=None, console=None):
    identity = {"type": "IAMUser", "arn": arn_user(user), "accessKeyId": f"{key}EXAMPLE{len(records):06d}"}
    if role:
        identity = {"type": "AssumedRole",
                    "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{user}",
                    "accessKeyId": f"ASIAEXAMPLE{len(records):06d}",
                    "sessionContext": {"sessionIssuer": {"type": "Role", "arn": arn_role(role)},
                                       "sourceIdentity": source_identity}}
    record = {"eventVersion": "1.08", "eventID": f"evt-{len(records):05d}",
              "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": f"{source}.amazonaws.com",
              "eventName": name, "awsRegion": REGION, "userIdentity": identity,
              "requestParameters": params or {}}
    if resource:
        record["resources"] = [{"ARN": resource}]
    if error:
        record["errorCode"] = error
    if console is not None:
        record["responseElements"] = {"ConsoleLogin": console}
    records.append(record)


def day(n, hour=10, minute=0):
    return EXPORTED - timedelta(days=n) + timedelta(hours=hour, minutes=minute)


for n in range(1, 30):
    event(day(n, 9), "alice", "signin", "ConsoleLogin", console="Success")
    for k in range(3):
        event(day(n, 10, k), "alice", "s3", "GetObject", resource=LAKE, params={"bucketName": "acme-analytics-lake"})
    event(day(n, 9), "bob", "signin", "ConsoleLogin", console="Success")
    event(day(n, 11), "bob", "iam", "ListUsers")
    event(day(n, 11, 5), "bob", "cloudtrail", "DescribeTrails")
    event(day(n, 2), "svc-reporting", "secretsmanager", "GetSecretValue", resource=DB_SECRET, key="AKIA")
    event(day(n, 14), "ci-deployer", "lambda", "UpdateFunctionCode", resource=PAYMENTS_FN, key="AKIA")
for n in (2, 5, 9, 12, 16, 20):
    event(day(n, 17), "ci-deployer", "signin", "ConsoleLogin", console="Success")
for n in (3, 10, 17):
    event(day(n, 15), "carol", "signin", "ConsoleLogin", console="Success")
    event(day(n, 15, 10), "carol", "s3", "GetObject", resource=LEDGER, params={"bucketName": "acme-payments-ledger"})
event(day(3, 13), "alice", "sts", "AssumeRole", params={"roleArn": arn_role("DataEngineerRole")})
for k in range(5):
    event(day(3, 13, 5 + k), "alice", "s3", "GetObject", resource=LEDGER, role="DataEngineerRole",
          source_identity="alice")
for n in range(8, 40, 4):
    event(day(n, 16), "eve", "signin", "ConsoleLogin", console="Success")
for k in range(7):
    event(day(1, 2, 2 * k), "eve", "signin", "ConsoleLogin", console="Failure")
event(day(1, 2, 20), "eve", "signin", "ConsoleLogin", console="Success")
event(day(1, 2, 25), "eve", "sts", "AssumeRole", params={"roleArn": arn_role("SupportRole")})
for k in range(120):
    event(day(1, 2, 30) + timedelta(seconds=25 * k), "eve", "dynamodb", "Scan", resource=CUSTOMERS,
          role="SupportRole", source_identity="eve")

files = {
    "manifest.json": {"account_id": ACCOUNT, "exported_at": EXPORTED.isoformat(),
                      "note": "Synthetic sample account for OpenZSP demos; generated by tools/make_aws_sample.py"},
    "authorization_details.json": authorization_details,
    "scps.json": scps,
    "resources.json": resources,
    "resource_policies.json": resource_policies,
    "cloudtrail.json": {"Records": sorted(records, key=lambda r: (r["eventTime"], r["eventID"]))},
}
OUT.mkdir(parents=True, exist_ok=True)
for name, content in files.items():
    (OUT / name).write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote {OUT} ({len(records)} CloudTrail records)")
