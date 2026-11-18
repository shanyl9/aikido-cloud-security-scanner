# Cloud Security Case: AWS Exposure Scanner (PoC)

## Background

This repository is my answer to the *Cloud Security Case*: design a lightweight cloud security scanner,
propose three checks, implement one as a small proof of concept, and discuss its limits and how it
would run at production scale.

The brief's central point is to go **beyond individual configuration checks to actual exposure**, and to
deliver accurate findings without false-positive noise. I chose **AWS** and a **networking** check that
does exactly that. The classic finding "security group allows `0.0.0.0/0` on port 22" is often a false
positive: the instance may have no public IP, sit in a subnet that only routes out through NAT, or be
behind a network ACL that blocks the port or the reply. This scanner follows the packet through every
control on the path and reports a finding only when all of them let it through, with the evidence for each.

| Brief | Section |
|---|---|
| 1. Propose three checks | [1. Proposed checks](#1-proposed-checks) |
| 2. Choose one, explain the approach | [2. Approach](#2-approach-effective-internet-exposure) |
| 3. Implement it, finding vs. similar non-finding | [3. Implementation and results](#3-implementation-and-results) |
| 4. Limits, missing data or permissions | [4. Limits](#4-limits-of-the-conclusion) |
| 5. Production scale (3,000 environments) | [5. Production scale](#5-production-scale-3000-environments) |
| Bonus: scan with Aikido | [Bonus](#bonus-aikido-scan) |

Written in Go. It runs on hand-written fixtures in the exact format of `aws ec2 describe-*` output,
so no AWS account is needed to try it.

---

## 1. Proposed checks

**A. Effective internet exposure of compute (implemented).**
*Risk:* an admin service (SSH, RDP, a database) reachable from the whole internet is a direct entry
point for brute force, credential stuffing and exploitation of unpatched services.
*Why first:* it is the most common real attack entry point, and also the noisiest naive check. Turning
"SG allows 0.0.0.0/0" into a verified, explained finding removes the most false positives per unit of
work, which is exactly the noise problem customers complain about.

**B. Exposed workload with a powerful IAM role (toxic combination).**
*Risk:* an internet-reachable instance whose instance profile allows `"Action": "*"`, `iam:PassRole` or broad
data access. One compromised host becomes an account takeover or a data breach.
*Why next:* it ranks risk by blast radius instead of listing misconfigurations one by one, and it builds
directly on A. A says which instances are reachable; B says how bad a compromise of each would be.

**C. Effectively public S3 bucket.**
*Risk:* data leakage (backups, Terraform state, logs, customer files) or tampering, if writes are public.
*Why:* high impact, and like A it is a case where settings override each other. A bucket policy with
`Principal: "*"` is not effective if Block Public Access `RestrictPublicBuckets` is on (account or
bucket level), or if a condition pins it to a VPC endpoint or an organization. A public ACL is ignored
when Object Ownership is `BucketOwnerEnforced`.

## 2. Approach: effective internet exposure

**Model.** A packet from an arbitrary internet address to `tcp/<port>` must pass six gates, and the reply must get back:

| # | Gate | Open when | Source API |
|---|---|---|---|
| 1 | Instance state | `running` | `ec2:DescribeInstances` |
| 2 | Security group | an attached SG (instance or any of its network interfaces) allows the port from a `/0` range; protocol `tcp`, `6` or `-1` | `ec2:DescribeSecurityGroups` |
| 3 | Public IP | public IPv4 or Elastic IP on the instance | `ec2:DescribeInstances` |
| 4 | Route table | the subnet's route table (explicit association, otherwise the VPC main table) sends `0.0.0.0/0` to an `igw-`. A narrower route to the IGW also counts, reported as partial. NAT, transit gateway, peering or a firewall endpoint do not count | `ec2:DescribeRouteTables` |
| 5 | NACL inbound | the lowest-numbered matching rule allows tcp/port from `0.0.0.0/0` | `ec2:DescribeNetworkAcls` |
| 6 | NACL outbound | NACLs are stateless: replies to the client's ephemeral ports (1024–65535) must be allowed. A partial range counts as open and is reported with the number of allowed ports | `ec2:DescribeNetworkAcls` |

**Verdict.**
- Only instances whose SG is open to the internet become candidates, so closed SGs produce no noise. If SG data is missing, every instance is a candidate.
- Every gate is evaluated and kept as evidence, even after one blocks.
- Any gate **BLOCKED** → **NOT_EXPOSED**, even if another gate's data is missing. No block, but a gate couldn't be evaluated → **UNKNOWN** (`UNVERIFIED`), naming the missing permission. All gates open → **EXPOSED** (`HIGH`), with copy-paste remediation.
- A stopped instance with an Elastic IP and every network gate open → `INFO`: it becomes exposed the moment it starts.

**Data and permissions.** Read-only: `ec2:DescribeInstances`, `DescribeSecurityGroups`,
`DescribeRouteTables` and `DescribeNetworkAcls`. The fixtures decode straight into the `aws-sdk-go-v2`
types, so a live collector (the same four calls per region, with paginators, under an assumed read-only
role) produces the same `Snapshot` and nothing in the check changes.

**Existing tools considered.**
- *Prowler / ScoutSuite* flag "SG open to 0.0.0.0/0", which is the noisy signal this check refines.
- *Amazon Inspector* produces network-reachability findings for EC2, but it must be enabled and paid for in every account.
- *Reachability Analyzer* checks one path at a time and is priced per analysis. *Network Access Analyzer* is a good validation oracle for this logic before production.
- I wrote the evaluation myself because the evidence trail and the UNKNOWN semantics are the product here, and because the same snapshot feeds checks B and C.

**Assumptions.** An arbitrary IPv4 client (rules count only with a `/0` CIDR). The primary network
interface's subnet. One account and region per snapshot. An open path means exposed: whether a process
listens on the port is not visible from AWS APIs.

## 3. Implementation and results

### How to run

Requires Go 1.24.4+.

```bash
go run ./cmd/scanner -snapshot fixtures/demo                  # 7 look-alike instances
go run ./cmd/scanner -snapshot fixtures/missing-permissions   # a denied API call
go run ./cmd/scanner -snapshot fixtures/demo -format json     # machine-readable output
go run ./cmd/scanner -snapshot fixtures/demo -ports 22:SSH,3389:RDP,5432:Postgres
go test ./...
```

### Code layout

```
cmd/scanner/                  CLI: flags, text/JSON output
internal/snapshot/            loads describe-*.json + errors.json into SDK types; tracks missing datasets
internal/exposure/            verdict: combines gate results into findings and remediation
internal/exposure/gates/      one file per AWS control; each returns OPEN / BLOCKED / UNKNOWN + evidence
fixtures/                     demo and missing-permission snapshots (see fixtures/README.md)
lab/                          CloudFormation lab recreating the cases in a real account + live snapshot script
```

### Results

Every instance in the demo snapshot ([fixture details](fixtures/README.md)) has the **same** security
group (tcp/22 from `0.0.0.0/0`), and each differs from the exposed baseline by exactly one control.
A naive scanner would flag all seven.

| Instance | Differs from the exposed baseline by | Verdict |
|---|---|---|
| `exposed` | (baseline) | **EXPOSED** |
| `main-rt` | subnet has no route table of its own; the VPC **main** table routes to the IGW | **EXPOSED** |
| `no-public-ip` | no public IP | NOT_EXPOSED |
| `nat-subnet` | Elastic IP, but `0.0.0.0/0` goes to a NAT gateway, so the reply cannot return through the IGW | NOT_EXPOSED |
| `nacl-deny` | NACL rule #90 denies tcp/22 before rule #100 allows all | NOT_EXPOSED |
| `nacl-no-ephemeral` | NACL allows 22 in, but only 443 out: the reply is dropped | NOT_EXPOSED |
| `stopped` | instance stopped (keeps its Elastic IP), everything else open | NOT_EXPOSED, severity INFO (latent) |
| `missing-permissions/exposed` | `ec2:DescribeNetworkAcls` denied | **UNKNOWN**, never "safe" |

The scanner flags **2 of the 7**, clears the other 5 with the exact blocking control as evidence, and
lists the open but unattached security group as "considered, no finding".

**Finding vs. apparently similar non-finding.** Same security group, both instances have a public IP;
the difference is where the subnet routes `0.0.0.0/0` (internet gateway vs. NAT gateway):

```
EXPOSED     [HIGH] i-0exposed000000001 (exposed)  tcp/22 SSH
  SSH (tcp/22) is reachable from any internet address: every gate on the path allows it.
    open     instance-state  running
    open     security-group  sg-0open0ssh000000001 (open-ssh) allows tcp 22-22 from 0.0.0.0/0
    open     public-ip       203.0.113.10
    open     route-table     rtb-0public000000001 via explicit subnet association: 0.0.0.0/0 -> igw-0a1b2c3d4e5f60001
    open     nacl-inbound    acl-0default00000001: rule #100 (allow all protocols, all ports) from 0.0.0.0/0
    open     nacl-outbound   acl-0default00000001: rule #100 (allow all protocols, all ports) permits replies to ephemeral ports 1024-65535
  Remediation:
    - Revoke the world-open rule on sg-0open0ssh000000001 (this affects every instance using the group), then allow tcp/22 only from known ranges: aws ec2 revoke-security-group-ingress --group-id sg-0open0ssh000000001 --protocol tcp --port 22-22 --cidr 0.0.0.0/0
    - Prefer AWS Systems Manager Session Manager or an EC2 Instance Connect Endpoint over a public SSH port.
    - If the instance does not need to be public, remove its public IP / Elastic IP or move it to a private subnet.

NOT_EXPOSED [NONE] i-0natsubnet0000001 (nat-subnet)  tcp/22 SSH
    ...
    BLOCKED  route-table     rtb-0private00000001 via explicit subnet association: 0.0.0.0/0 -> nat-0a1b2c3d4e5f60001 (not an internet gateway; outbound-only or private path)
    ...

Summary: 2 exposed, 0 unknown, 5 not exposed (of 7 candidates)
```

## 4. Limits of the conclusion

**Could hide real exposure (false negatives):**
- **Load balancers:** an internet-facing ALB/NLB, CloudFront or Global Accelerator in front of a *private* instance. Only the direct path is followed.
- **Inspection appliances:** a default route to an AWS Network Firewall or Gateway Load Balancer endpoint (`vpce-…`) is treated as blocked, although the firewall may let port 22 through.
- **IPv6:** `::/0` rules and routes are out of scope here; the same gate model applies.
- **Partial ranges:** narrower public CIDRs (e.g. a `/8`) and SG prefix lists are treated as not matching an arbitrary client.
- **Multiple network interfaces:** the public IP may come from any interface, but routes and NACLs are evaluated for the primary subnet only.

**Could make an EXPOSED finding safe in practice (false positives):** a host firewall, or nothing
listening on the port. Key-only SSH or MFA lower the chance of compromise, but not the exposure.

**Time:** the result is a point-in-time snapshot.

**Missing data or permissions.** Absence of data is never treated as a pass:
- A denied call (`UnauthorizedOperation`) is recorded in `errors.json`. Every gate that depends on it reports **UNKNOWN** with the exact missing action, and the report lists the data gap.
- A gate seen blocking still wins: no public IP is NOT_EXPOSED even when the NACLs are unknown.
- If `DescribeInstances` itself is missing, the scan fails loudly instead of returning "0 findings".
- For a customer I would report coverage separately: "N accounts or regions not fully scanned, because of X".

## 5. Production scale: 3,000 environments

- **Access:** a read-only role in every account, deployed with CloudFormation StackSets from the customer's AWS Organization (the management account needs its own stack). The scanner assumes it with `sts:AssumeRole` and an `ExternalId`, with no stored keys. The role also needs `account:ListRegions`.
- **Jobs:** one job per (account, region), 3,000 × 17 default regions ≈ 50k, skipping disabled or empty regions. Jobs go on a durable queue for stateless, horizontally scaled workers, with retries, backoff and a dead-letter queue.
- **Collect separately from evaluating:** collectors only call `Describe*` and store a versioned snapshot. Evaluators are pure functions over it, like this PoC, so improving a check needs no new AWS calls, and checks B and C reuse the same data.
- **AWS rate limits:** these apply per account and region, so use a token bucket per (account, region), paginate, back off with jitter on `RequestLimitExceeded`, and spread full scans over the day.
- **Incremental:** CloudTrail events via EventBridge (`RunInstances`, `AuthorizeSecurityGroupIngress`, `ModifyNetworkInterfaceAttribute`, `CreateRoute`, `ReplaceNetworkAclEntry`, `AssociateAddress`, …; this needs a trail and a rule in each region) trigger a rescan of just that account and region. A periodic full scan reconciles.
- **Findings lifecycle:** a stable fingerprint (account, region, instance, port) with dedup and first-seen / last-seen. Auto-resolve **only after a complete, error-free scan**: a failed scan must not close findings. Group by root cause, since one SG exposing 40 instances is one fix.

**Before production, in priority order:**
1. Correctness on real accounts: diff against Network Access Analyzer.
2. Close the biggest false negatives: load balancers, then IPv6.
3. Coverage and permission-gap reporting, so "not scanned" is never read as "secure".
4. Rate limiting and tenant isolation.
5. Observability: scan duration, errors by API, coverage per tenant.

## What I would do next

1. A Go live collector (`-aws-profile`, `-region`). Today [`lab/snapshot.sh`](lab/snapshot.sh) does this with the AWS CLI, and [`lab/`](lab/README.md) reproduces the demo cases in a real account.
2. Internet-facing ALB/NLB path and IPv6.
3. Check B on top of A: reachable instance × instance profile permissions gives a prioritised severity.
4. Group findings by root-cause security group.

## Bonus: Aikido scan

**What I did:** created a personal AWS sandbox account (Free plan) and deployed the
[live lab](lab/README.md) in `eu-north-1`. It has four instances sharing one SSH-open security group:
one really exposed, three blocked by a different control each, plus an orphan open group. Then I
connected the account to Aikido through its read-only CloudFormation role (two attempts).

**Result: Aikido could not connect**, so no scan ran yet. The most likely cause is that the new AWS
account was still being verified (the console said up to two days, and CloudShell would not start
meanwhile). The Free plan's restrictions may also play a part: one region, 8 vCPUs, and IAM roles
managed by the console.

**Observation:** this is section 4's "missing permissions" case seen from the product side. Aikido said
explicitly that it could not connect, which is right, but the same page showed a green **"0 issues"**
badge, which reads as "secure" when it means "not scanned". This scanner reports that state as `UNKNOWN`.

**To do, once the account is verified:**
1. Reconnect Aikido and let it scan.
2. Run this scanner on the same lab with [`lab/snapshot.sh`](lab/snapshot.sh). So far it has only run on fixtures.
3. Compare the two tools on each lab instance. Does Aikido flag the open SSH group on all four, or only on the one that is really reachable? Does it ignore the orphan group?
