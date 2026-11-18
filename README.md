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
- Only instances where gate 2 is open become candidates, so instances with closed SGs produce no noise. (If the SG data itself is missing, every instance is a candidate and is UNKNOWN unless another gate blocks.)
- Every gate is evaluated and kept as evidence, even after one blocks, so the reader sees the whole picture.
- Any gate seen **BLOCKED** gives **NOT_EXPOSED**. A known block is enough, even if another gate's data is missing.
- No block, but a gate could not be evaluated, gives **UNKNOWN** (severity `UNVERIFIED`), naming the missing permission.
- All gates open gives **EXPOSED** (`HIGH`), with copy-paste remediation.
- A stopped instance with every network gate open is reported as `INFO`: it becomes exposed the moment it starts. This only applies with an Elastic IP; an auto-assigned public IP is released on stop.

**Permissions.** Read-only, four actions (the scanner never calls a mutating API):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
               "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls"],
    "Resource": "*"
  }]
}
```

**Data in a real integration.** The fixtures use the exact response format of `aws ec2 describe-instances`
(etc.) and decode straight into the `aws-sdk-go-v2` types. A live collector would call the same four APIs
per region with paginators (`ec2.NewDescribeInstancesPaginator`, …) under an assumed read-only role,
and write the same `Snapshot`. Nothing in the check changes.

**Existing tools considered.**
- *Prowler / ScoutSuite* flag "SG open to 0.0.0.0/0". That is the noisy signal this check refines. They could be used as candidate input.
- *Amazon Inspector* produces network-reachability findings for EC2 and is the closest native equivalent. It has to be enabled, and paid for, in every account, so it is a good cross-check rather than something a third-party scanner can rely on.
- *VPC Reachability Analyzer* proves one source→destination path at a time and is priced per analysis, so it doesn't fit a sweep of every instance.
- *Network Access Analyzer* can express "internet → ENI" scopes and is a good **validation oracle** for this logic before production.
- I wrote the evaluation myself because the evidence trail and the UNKNOWN semantics are the product here, and because the same normalized snapshot feeds checks B and C.

**Assumptions.**
- "The internet" means an arbitrary IPv4 client. A rule counts only if its CIDR is `/0`.
- The instance's subnet is the primary network interface's subnet.
- An open path means exposed. Whether a process actually listens on the port is not visible from AWS APIs.
- One account, one region per snapshot.

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

### Test scenarios

Every instance in the demo snapshot ([fixture details](fixtures/README.md)) has the **same** security
group (tcp/22 from `0.0.0.0/0`), and each differs from the exposed baseline by exactly one control.
A naive scanner would flag all seven.

### Results

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

The scanner flags **2 of the 7** instances a naive check would flag, clears the other 5 with the exact
blocking control as evidence, and reports the open but unattached security group as "considered, no finding".

**Finding vs. apparently similar non-finding.** Same security group, both instances have a public
IP; the difference is where the subnet routes `0.0.0.0/0` (internet gateway vs. NAT gateway):

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

...

NOT_EXPOSED [NONE] i-0natsubnet0000001 (nat-subnet)  tcp/22 SSH
  Security group is open to the internet on tcp/22, but traffic is blocked at route-table: rtb-0private00000001 via explicit subnet association: 0.0.0.0/0 -> nat-0a1b2c3d4e5f60001 (not an internet gateway; outbound-only or private path)
    open     instance-state  running
    open     security-group  sg-0open0ssh000000001 (open-ssh) allows tcp 22-22 from 0.0.0.0/0
    open     public-ip       203.0.113.20 (Elastic IP)
    BLOCKED  route-table     rtb-0private00000001 via explicit subnet association: 0.0.0.0/0 -> nat-0a1b2c3d4e5f60001 (not an internet gateway; outbound-only or private path)
    open     nacl-inbound    acl-0default00000001: rule #100 (allow all protocols, all ports) from 0.0.0.0/0
    open     nacl-outbound   acl-0default00000001: rule #100 (allow all protocols, all ports) permits replies to ephemeral ports 1024-65535

...

Summary: 2 exposed, 0 unknown, 5 not exposed (of 7 candidates)
```

**Missing permission.** The same exposed instance, with `ec2:DescribeNetworkAcls` denied:

```
UNKNOWN     [UNVERIFIED] i-0exposed000000001 (exposed)  tcp/22 SSH
  No gate was seen blocking tcp/22, but some gates could not be evaluated. Treat as potentially exposed until verified.
    ...
    unknown  nacl-inbound    DescribeNetworkAcls failed with UnauthorizedOperation (scanner needs ec2:DescribeNetworkAcls)
    unknown  nacl-outbound   DescribeNetworkAcls failed with UnauthorizedOperation (scanner needs ec2:DescribeNetworkAcls)
```

## 4. Limits of the conclusion

**Could make a NOT_EXPOSED instance actually exposed (false negatives):**
- **Load balancers:** an internet-facing ALB/NLB, CloudFront or Global Accelerator in front of a *private* instance. This check only follows the direct path.
- **Inspection appliances:** when the subnet's default route points to an AWS Network Firewall or Gateway Load Balancer endpoint (`vpce-…`), the route gate reports BLOCKED, although the firewall may let port 22 through.
- **IPv6:** a `::/0` SG rule with a `::/0` route to the IGW. Out of scope here, but the same gate model applies.
- **Partial ranges:** an SG or NACL rule for a narrower but still public range (e.g. a `/8`), or SG rules via prefix lists. These are treated as not matching "an arbitrary client", which understates partial exposure.
- **Multiple network interfaces:** a second ENI in another subnet with its own public IP. The public IP may come from any interface, but routes and NACLs are evaluated for the primary subnet only.

**Could make an EXPOSED instance actually safe (false positives):**
- A host firewall (iptables, Windows Firewall), or nothing listening on the port.
- Even when the port is reachable, key-only SSH or MFA lower the likelihood of compromise, but not the exposure.

**Time:** the result is a point-in-time snapshot. A rule added a minute later is not seen until the next scan.

**Missing data or permissions.** Absence of data is never treated as a pass:
- A denied API call (`UnauthorizedOperation`) is recorded in `errors.json`. Every gate that depends on it reports **UNKNOWN** with the exact missing action, the instance gets `UNVERIFIED` severity, and the report lists the data gap.
- A gate seen blocking still wins: no public IP is NOT_EXPOSED even when the NACLs are unknown.
- If `DescribeInstances` itself is missing, the scan of that account fails loudly instead of returning "0 findings".
- For a customer I would surface coverage separately: "N accounts or regions not fully scanned, because of X".

## 5. Production scale: 3,000 environments

**Onboarding and access.**
- Deploy one read-only role per account via CloudFormation StackSets from the customer's AWS Organization. Service-managed StackSets skip the management account, so it needs its own stack.
- The scanner assumes the role with `sts:AssumeRole` and an `ExternalId`, using short-lived credentials and no stored keys.
- Beyond the four EC2 actions, the role needs `account:ListRegions` for region discovery.

**Work model.**
- One job per (account, region): 3,000 accounts × 17 default-enabled regions ≈ 50k small jobs.
- Skip regions that are disabled (`account:ListRegions`) or empty.
- Put the jobs on a durable queue, consumed by stateless workers that scale horizontally.
- Retry with backoff and send poison jobs to a dead-letter queue.

**Separate collection from evaluation.**
- Collectors only call `Describe*` and store a normalized, versioned snapshot per account and region.
- Evaluators are pure functions over snapshots, like this PoC. Improving a check means re-evaluating stored data, with no new AWS calls.
- Cross-resource checks (B, C) join snapshots without re-collecting.

**Respect AWS limits.**
- EC2 API rate limits apply per account and region. Use a token bucket per (account, region), paginate, and back off with jitter on `RequestLimitExceeded`.
- Spread the full scans over the day instead of starting all 50k at 00:00.

**Be incremental.**
- Use CloudTrail API events delivered through EventBridge to rescan only the affected account and region within minutes. Examples: `RunInstances`, `StartInstances`, `AuthorizeSecurityGroupIngress`, `ModifyNetworkInterfaceAttribute`, `CreateRoute`, `ReplaceNetworkAclEntry`, `AssociateAddress`. This needs a CloudTrail trail and an EventBridge rule in each region.
- Keep a periodic full scan as reconciliation. AWS Config aggregators are an alternative inventory source.

**Findings lifecycle.**
- Give each finding a stable fingerprint (account, region, instance, port). Deduplicate, track first seen and last seen, and auto-resolve **only after a complete, error-free scan** of that account and region. A failed scan must not close findings.
- Group findings by root cause (one SG exposing 40 instances is one fix), to reduce noise further.

**Before production, in priority order:**
1. **Correctness on real accounts.** Run against a few real environments and diff against Network Access Analyzer. Every disagreement is a bug or a documented limit.
2. **Close the biggest false negatives:** internet-facing load balancers, then IPv6.
3. **Coverage and permission-gap reporting**, so a customer never mistakes "not scanned" for "secure".
4. **Rate limiting and isolation:** one noisy tenant or throttled account must not stall the others. Tenant data is isolated.
5. **Observability:** scan duration, error rate by API and code, and coverage per tenant.

## What I would do next

1. A Go live collector (`-aws-profile`, `-region`) producing the same snapshot. Today [`lab/snapshot.sh`](lab/snapshot.sh) does this with the AWS CLI, and [`lab/`](lab/README.md) reproduces the demo cases in a real account.
2. Internet-facing ALB/NLB path and IPv6.
3. Check B on top of A: reachable instance × instance profile permissions gives a prioritised severity.
4. Group findings by root-cause security group.

## Bonus: Aikido scan

**What I did.**
- Created a new personal AWS account (Free plan) as a sandbox.
- Deployed the [live lab](lab/README.md) in `eu-north-1`: four instances sharing one SSH-open security group. One is really exposed, and three are each blocked by a different control (a main route table without an IGW route, a NACL deny, a NACL without a reply path). There is also an open security group attached to nothing.
- Connected the account to Aikido through its read-only CloudFormation role (two attempts).

**Result: Aikido could not connect**, so no scan ran yet. The most likely cause is that the new AWS
account was still being verified: the console said this can take up to two days, and CloudShell would
not start meanwhile. The Free plan's restrictions I ran into may also play a part: the account was
pinned to one region, limited to 8 vCPUs, and IAM roles were managed by the console.

**Observation.** This is section 4's "missing permissions" case seen from the product side. Aikido said
explicitly that it could not connect, which is right. But the same page also showed a green
**"0 issues"** badge, which at a glance reads as "secure" when it means "not scanned". This scanner
reports that state as `UNKNOWN`, never as zero findings.

**To do, once the account is verified:**
1. Reconnect Aikido and let it scan.
2. Run this scanner on the same live lab with [`lab/snapshot.sh`](lab/snapshot.sh). So far it has only run on fixtures.
3. Compare the two tools on each lab instance (expected verdicts in [lab/README.md](lab/README.md)). Does Aikido flag the open SSH group on all four instances, or only on the one that is really reachable? Does it ignore the orphan group?
