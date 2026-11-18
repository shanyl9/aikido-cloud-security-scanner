# Fixtures

Each file is the unmodified response shape of a read-only EC2 API call, as printed by
`aws ec2 describe-<x> --output json`. They decode directly into the `aws-sdk-go-v2/service/ec2`
output types, so a live collector can replace the fixture loader without changing the check.

| File | API call (IAM permission) |
|---|---|
| `describe-instances.json` | `ec2:DescribeInstances` |
| `describe-security-groups.json` | `ec2:DescribeSecurityGroups` |
| `describe-route-tables.json` | `ec2:DescribeRouteTables` |
| `describe-network-acls.json` | `ec2:DescribeNetworkAcls` |
| `errors.json` | not an AWS response: records API calls that failed during collection |

Public IPs use the documentation range `203.0.113.0/24`; account `111122223333` is fictional.

## `demo/`: one VPC, same open security group everywhere

Every instance has `sg-0open0ssh000000001` (tcp/22 from `0.0.0.0/0`). Each case differs from the
baseline in exactly one thing.

| Instance | Subnet | Route table | NACL | Differs by | Expected |
|---|---|---|---|---|---|
| `i-0exposed000000001` | public | `rtb-0public…` → IGW | default-open | baseline | **EXPOSED** |
| `i-0nopublicip000001` | public | `rtb-0public…` → IGW | default-open | no public IP | NOT_EXPOSED |
| `i-0natsubnet0000001` | private-nat | `rtb-0private…` → NAT | default-open | has EIP, but 0.0.0.0/0 goes to NAT | NOT_EXPOSED |
| `i-0mainrt0000000001` | main-rt | none explicit → **main** `rtb-0main…` → IGW | default-open | implicit main route table | **EXPOSED** |
| `i-0nacldeny00000001` | nacl-deny-ssh | `rtb-0public…` → IGW | rule 90 denies tcp/22 before rule 100 allow-all | NACL deny | NOT_EXPOSED |
| `i-0naclnoeph0000001` | nacl-no-ephemeral | `rtb-0public…` → IGW | in: 22 allowed; out: only 443 | no return path (NACL is stateless) | NOT_EXPOSED |
| `i-0stopped000000001` | public | `rtb-0public…` → IGW | default-open | stopped (keeps its EIP) | NOT_EXPOSED (latent) |

Also present: `sg-0orphan0open00001` allows all traffic from `0.0.0.0/0` but is attached to
nothing, so it must not produce a finding.

## `missing-permissions/`

The same baseline instance, but `ec2:DescribeNetworkAcls` returned `UnauthorizedOperation`
(see `errors.json`) so there is no NACL file. Expected: **UNKNOWN**, never NOT_EXPOSED.
