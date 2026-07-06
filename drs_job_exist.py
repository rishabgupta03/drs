
#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError, BotoCoreError

CONTROL_NAME = "DRS Region Has Enabled Recovery Job"

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=True)["Regions"]

    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    """
    Turns a boto3/botocore exception into a (status, evidence) pair.
    Kept intentionally compact: one place decides how an error maps
    to COMPLIANT/NON_COMPLIANT/SKIPPED instead of scattering logic.
    """
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "UnknownError")

        # DRS has literally never been set up in this region/account.
        # That directly answers the control question: "no", so it's
        # a real finding, not something to skip.
        if code == "UninitializedAccountException":
            return "NON_COMPLIANT", "DRS is not initialized/enabled in this region"

        if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
            return "SKIPPED", f"Access denied while querying DRS ({code})"

        if code in ("ThrottlingException", "TooManyRequestsException"):
            return "SKIPPED", f"Throttled by AWS API ({code})"

        return "SKIPPED", f"Could not evaluate region: {code}"

    # Non-ClientError failures (endpoint issues, connection errors, etc.)
    if isinstance(e, BotoCoreError):
        return "SKIPPED", f"Could not reach DRS endpoint: {e}"

    return "SKIPPED", f"Unexpected error: {e}"


def is_recovery_job(job):
    """
    A DRS 'Job' covers drills, recoveries, terminations, etc.
    Only START_RECOVERY jobs count as an actual recovery job;
    drills/tests must not count toward compliance.
    """
    return job.get("initiatedBy") == "START_RECOVERY"


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_control(session):

    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        resource_id = region
        resource_arn = f"arn:aws:drs:{region}:{account_id}:region/{region}"

        try:
            client = session.client("drs", region_name=region)

            recovery_job_count = 0

            paginator = client.get_paginator("describe_jobs")
            for page in paginator.paginate():
                for job in page.get("items", []):
                    if is_recovery_job(job):
                        recovery_job_count += 1

            total_checked += 1

            if recovery_job_count > 0:
                status = "COMPLIANT"
                compliant += 1
                evidence = f"DRS enabled with {recovery_job_count} recovery job(s) found"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = "DRS is enabled but no recovery jobs (START_RECOVERY) were found"

        except (ClientError, BotoCoreError) as e:
            status, evidence = classify_error(e)
            total_checked += 1

            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
                skipped += 1

        results.append({
            "Account": account_id,
            "Region": region,
            "ResourceId": resource_id,
            "ResourceArn": resource_arn,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================

def write_csv(results, account_id):
    filename = f"drs_job_exist_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "ResourceId", "ResourceArn", "Status", "Evidence"]
        )
        writer.writeheader()
        writer.writerows(results)

    return filename


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Check whether each enabled AWS region has DRS enabled with at least one recovery job."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 52)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 52)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Generated   : {csv_file}")
    print("=" * 52 + "\n")


if __name__ == "__main__":
    main()
