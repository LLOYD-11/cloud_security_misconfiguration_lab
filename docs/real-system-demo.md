# Bounded AWS Real-System Demo

## Status

**Prepared, not executed.** The deployment template, safety assertions,
collection boundary, analysis command, sanitization requirements, and teardown
checks are reviewable. No live AWS evidence or result is claimed in the current
repository.

Completion requires an explicitly authorized disposable AWS account, a local
AWS CLI session controlled by the account owner, reviewed sanitized evidence,
and recorded teardown. Synthetic or native-shaped fixtures must not be relabelled
as real-system evidence.

## Demonstration Objective

Create one intentionally broad SSH permission on a disposable, unattached
security group in an operator-selected VPC; collect a complete regional
`DescribeSecurityGroups` response; analyze that export offline; verify the
expected `NET-001` finding for the demo group; then delete the stack and confirm
the group no longer exists.

This demonstrates a real AWS configuration boundary without launching a
workload or sending traffic. It does not demonstrate production accuracy,
internet reachability, compromise, or all four analyzer modules.

## Safety Design

The versioned
[`network-demo-stack.json`](../demo/real-system/network-demo-stack.json) accepts
one existing VPC ID through the documented
[`AWS::EC2::VPC::Id` parameter type](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-supplied-parameter-types.html)
and creates exactly one
[`AWS::EC2::SecurityGroup`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html).
The group has public TCP/22 ingress, private-range-only egress, and no declared
attachment.

It creates no VPC, EC2 instance, network interface, subnet, route table,
internet gateway, NAT gateway, endpoint, load balancer, public IPv4 address,
IAM identity, S3 object, secret, or persistent log destination. Local
regression tests enforce the exact one-resource inventory and rule shape. The
operator must separately verify after deployment that no network interface is
using the group.

AWS states that there is no additional charge for using
[security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html).
CloudFormation has no additional charge for `AWS::*` resource providers,
although underlying resources remain subject to their own current prices;
review the live
[CloudFormation pricing page](https://aws.amazon.com/cloudformation/pricing/)
before execution. Do not treat this design as a billing guarantee.

## Preconditions

- Use a dedicated disposable personal lab account owned by the operator and
  covered by explicit authorization for this demonstration.
- Do not use an employer, client, university, shared production, or course
  account.
- Review the account's current budget alerts and AWS pricing before deployment.
- Install and configure
  [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
  locally. Do not paste credentials into this repository, shell history, issue,
  or chat.
- Select one Region and keep deployment, collection, and deletion in that same
  Region.
- Select an existing VPC that the operator is authorized to use. The template
  does not change or delete the VPC resource's configuration; it temporarily
  creates one security group associated with that VPC.
- Stop if the identity, account, Region, template, or expected resource list is
  not exactly understood.

## 1. Review Locally

Validate the JSON syntax and run the template safety regressions:

```bash
python3 -m json.tool demo/real-system/network-demo-stack.json >/dev/null
.venv/bin/python -m unittest tests.test_real_system_demo
```

Confirm that the raw evidence location is ignored before collecting anything:

```bash
mkdir -p .local/real-system-demo/raw
git check-ignore -v .local/real-system-demo/raw/
```

## 2. Confirm Identity And Region

Replace `PROFILE_NAME` with a locally configured profile and inspect the result
yourself. Do not commit or publish the account ID.

```bash
aws sts get-caller-identity --profile PROFILE_NAME
aws configure get region --profile PROFILE_NAME
aws ec2 describe-vpcs \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --query "Vpcs[].{VpcId:VpcId,IsDefault:IsDefault,State:State}"
```

After selecting `VPC_ID`, verify that the VPC has no network interfaces. The
expected result is `0`.

```bash
aws ec2 describe-network-interfaces \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --filters Name=vpc-id,Values=VPC_ID \
  --query "length(NetworkInterfaces)" \
  --output text
```

The caller needs only the CloudFormation and EC2 permissions required to
create, inspect, and delete the one declared resource. Do not use long-lived
root credentials.

Choose a new stack name for this run, replace the example timestamp, and verify
that it does not already exist. The expected result of `describe-stacks` is a
stack-not-found error. Do not deploy if the command succeeds.

```bash
STACK_NAME=cloud-security-lab-demo-20260906-140000

aws cloudformation describe-stacks \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME"
```

Once stack creation starts, deletion and final verification remain mandatory
even if collection or analysis fails.

## 3. Deploy The Bounded Stack

```bash
aws cloudformation deploy \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME" \
  --template-file demo/real-system/network-demo-stack.json \
  --parameter-overrides VpcId=VPC_ID \
  --no-fail-on-empty-changeset
```

Inspect the actual stack inventory before collection:

```bash
aws cloudformation list-stack-resources \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME"
```

Stop and delete the stack if anything other than the single security group is
present.

Obtain the group ID from the stack output and verify that no network interface
uses it. The expected result is `0`.

```bash
aws cloudformation describe-stacks \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='SecurityGroupId'].OutputValue | [0]" \
  --output text

aws ec2 describe-network-interfaces \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --filters Name=group-id,Values=SECURITY_GROUP_ID \
  --query "length(NetworkInterfaces)" \
  --output text
```

Do not continue if the result is not `0`.

## 4. Collect Complete Regional Evidence

Use restrictive local file permissions. The response is account-sensitive and
must remain under `.local/`.

```bash
umask 077
aws ec2 describe-security-groups \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --output json \
  --no-cli-pager \
  > .local/real-system-demo/raw/describe-security-groups.json
```

Do not add filters, group IDs, `--max-items`, or `--no-paginate`. The analyzer's
native contract represents a complete, unfiltered regional response; a filtered
response could hide groups and produce false negatives.

Record the exact UTC collection time separately:

```bash
date -u +%Y-%m-%dT%H:%M:%SZ
```

## 5. Analyze Offline

Disconnecting from AWS is optional but makes the boundary easy to demonstrate.
Replace `COLLECTION_TIME` with the recorded UTC value.

```bash
python3 -m cloud_security_lab analyze network \
  .local/real-system-demo/raw/describe-security-groups.json \
  --input-format aws \
  --region ap-southeast-2 \
  --observed-at COLLECTION_TIME \
  --normalized-output reports/generated/real_system_network_environment.json \
  --output reports/generated/real_system_network_findings.json \
  --summary-output reports/generated/real_system_network_summary.json
```

Use the previously recorded demo security-group ID to verify that its finding
is `NET-001`. Do not publish the real ID.

The exact total finding count is not predeclared because a complete account
snapshot can contain default or pre-existing security groups. The required demo
observation is narrower: the stack-created group should produce one high
`NET-001` finding for public TCP/22. With no independent reachability context,
the finding must remain `not_assessed` rather than claim internet reachability.

## 6. Delete And Verify

Delete immediately after collection:

```bash
aws cloudformation delete-stack \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME"

aws cloudformation wait stack-delete-complete \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --stack-name "$STACK_NAME"
```

AWS documents that
[`delete-stack`](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/delete-stack.html)
starts stack deletion. The wait command must complete successfully, and a final
regional resource check must show that the recorded demo group no longer
exists. The selected pre-existing VPC must still exist, and this procedure must
not make any VPC configuration change outside the temporary group lifecycle.

```bash
aws ec2 describe-security-groups \
  --profile PROFILE_NAME \
  --region ap-southeast-2 \
  --group-ids SECURITY_GROUP_ID
```

The final command is expected to fail with a group-not-found response. Any
successful result requires investigation and manual cleanup before the demo can
be called complete.

## 7. Public Evidence Requirements

Do not publish the raw response. A future result can be marked complete only
after manual review produces a small sanitized evidence package containing:

- execution date, AWS CLI version, Region, authorization statement, and the
  template commit SHA;
- a statement that the account and resources were disposable and contained no
  real workload or data;
- a documented substitution procedure and fictional account, VPC, and
  security-group identifiers, while the private real-to-fictional mapping stays
  outside Git;
- the retained rule fields needed to reproduce `NET-001`, with unrelated
  account resources removed and that reduction explicitly disclosed;
- the analyzer command, package commit, normalized result, finding, and
  coverage summary;
- stack resource inventory before analysis and deletion verification after it;
  and
- a privacy review confirming that no credential, account ID, ARN, user name,
  organization name, local path, or unrelated resource entered Git history.

The public artifact must say that it is sanitized real-system evidence and that
the published subset is not a complete account snapshot. It must not be added
to the frozen M12 corpus or used to recalculate the `2.1.1` evaluation score.
