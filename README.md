# Cloud security scanner PoC: is that open port *actually* reachable?

A small AWS scanner, written in Go, that answers one question with evidence: **can an arbitrary internet
client reach an administrative port (SSH 22, RDP 3389) on this EC2 instance?**

A security group allowing `0.0.0.0/0` on port 22 is the most common cloud "finding", and often a
false positive. The instance may have no public IP, sit in a subnet that only routes out through NAT,
or be behind a network ACL that blocks the port or the reply. This scanner follows the packet through
every control on the path and reports a finding only when all of them let it through.

## Quick start

Requires Go 1.24+. No AWS account needed: the scanner runs on recorded API responses (see [fixtures](fixtures/README.md)).

```bash
go run ./cmd/scanner -snapshot fixtures/demo                  # 7 look-alike instances
go run ./cmd/scanner -snapshot fixtures/missing-permissions   # a denied API call
go run ./cmd/scanner -snapshot fixtures/demo -format json     # machine-readable
go run ./cmd/scanner -snapshot fixtures/demo -ports 22:SSH,3389:RDP,5432:Postgres
go test ./...
```

## Example: same security group, different verdicts

Every instance in `fixtures/demo` has the same security group (tcp/22 from `0.0.0.0/0`). Only two are reachable.

```
EXPOSED     [HIGH] i-0exposed000000001 (exposed)  tcp/22 SSH
  SSH (tcp/22) is reachable from any internet address: every layer on the path allows it.
    open     instance-state  running
    open     security-group  sg-0open0ssh000000001 (open-ssh) allows tcp 22-22 from 0.0.0.0/0
    open     public-ip       203.0.113.10
    open     route-table     rtb-0public000000001 via explicit subnet association: 0.0.0.0/0 -> igw-0a1b2c3d4e5f60001
    open     nacl-inbound    acl-0default00000001: rule #100 (allow all protocols, all ports) from 0.0.0.0/0
    open     nacl-outbound   acl-0default00000001: rule #100 (allow all protocols, all ports) permits replies to ephemeral ports 1024-65535
  Remediation:
    - Restrict sg-0open0ssh000000001 to known source ranges: aws ec2 revoke-security-group-ingress --group-id sg-0open0ssh000000001 --protocol tcp --port 22-22 --cidr 0.0.0.0/0
    - Prefer AWS Systems Manager Session Manager or an EC2 Instance Connect Endpoint over a public SSH port.
    - If the instance does not need to be public, remove its public IP / Elastic IP or move it to a private subnet.

NOT_EXPOSED [NONE] i-0natsubnet0000001 (nat-subnet)  tcp/22 SSH
  Security group is open to the internet on tcp/22, but traffic is blocked at route-table: rtb-0private00000001 via explicit subnet association: 0.0.0.0/0 -> nat-0a1b2c3d4e5f60001 (not an internet gateway; outbound-only or private path)
    open     instance-state  running
    open     security-group  sg-0open0ssh000000001 (open-ssh) allows tcp 22-22 from 0.0.0.0/0
    open     public-ip       203.0.113.20 (Elastic IP)
    BLOCKED  route-table     rtb-0private00000001 via explicit subnet association: 0.0.0.0/0 -> nat-0a1b2c3d4e5f60001 (not an internet gateway; outbound-only or private path)
    ...

Considered, no finding:
  sg-0orphan0open00001 allows all traffic from 0.0.0.0/0 but is not attached to any EC2 instance in this snapshot (other resource types are not evaluated)

Summary: 2 exposed, 0 unknown, 5 not exposed (of 7 candidates with an internet-open security group)
```

All demo cases:

| Instance | Differs from the exposed baseline by | Verdict |
|---|---|---|
| `exposed` | (baseline) | **EXPOSED** |
| `main-rt` | subnet has no route table of its own; the VPC **main** table routes to the IGW | **EXPOSED** |
| `no-public-ip` | no public IP | NOT_EXPOSED |
| `nat-subnet` | Elastic IP, but `0.0.0.0/0` goes to a NAT gateway | NOT_EXPOSED |
| `nacl-deny` | NACL rule #90 denies tcp/22 before rule #100 allows all | NOT_EXPOSED |
| `nacl-no-ephemeral` | NACL allows 22 in, but only 443 out: the reply is dropped | NOT_EXPOSED |
| `stopped` | instance stopped, everything else open | NOT_EXPOSED, severity INFO (latent) |
| `missing-permissions/exposed` | `ec2:DescribeNetworkAcls` denied | **UNKNOWN**, never "safe" |

---

## 1. Three proposed checks

**A. Effective internet exposure of compute (implemented).**
*Risk:* an admin service (SSH, RDP, a database) reachable from the whole internet is a direct entry
point for brute force, credential stuffing and exploitation of unpatched services.
*Why first:* it is the most common real attack entry point, and also the noisiest naive check
("SG allows 0.0.0.0/0"). Turning it into a verified, explained finding removes the most false positives
per unit of work, which is exactly the noise problem customers complain about.

**B. Exposed workload with a powerful IAM role (toxic combination).**
*Risk:* an internet-reachable instance whose instance profile allows `*:*`, `iam:PassRole` or broad
data access. One compromised host becomes an account takeover or a data breach.
*Why next:* it ranks risk by blast radius instead of listing misconfigurations one by one. It reuses
A's output directly: A says which instances are reachable, B says how bad a compromise of each would be.

**C. Effectively public S3 bucket.**
*Risk:* data leakage (backups, Terraform state, logs, customer files) or tampering, if writes are public.
*Why:* high impact, and like A it is a case where settings override each other. A bucket policy with
`Principal: "*"` is not public if account-level Block Public Access is on, or if a condition pins it to a
VPC endpoint or an organization. A public ACL is ignored when Object Ownership is `BucketOwnerEnforced`.

## 2. Approach for check A

**Model.** A packet from an arbitrary internet address to `tcp/<port>` must pass six gates, and the reply must get back:

| # | Gate | Open when | Source API |
|---|---|---|---|
| 1 | Instance state | `running` | `ec2:DescribeInstances` |
| 2 | Security group | an attached SG (instance or any of its network interfaces) allows the port from a `/0` range; protocol `tcp`, `6` or `-1` | `ec2:DescribeSecurityGroups` |
| 3 | Public IP | public IPv4 or Elastic IP on the instance | `ec2:DescribeInstances` |
| 4 | Route table | the subnet's route table (explicit association, otherwise the VPC main table) sends `0.0.0.0/0` to an `igw-`. NAT, transit gateway or peering do not count | `ec2:DescribeRouteTables` |
| 5 | NACL inbound | the lowest-numbered matching rule allows tcp/port from `0.0.0.0/0` | `ec2:DescribeNetworkAcls` |
| 6 | NACL outbound | NACLs are stateless: the reply to the client's ephemeral port (1024–65535) must be allowed | `ec2:DescribeNetworkAcls` |

**Verdict.**
- Only instances where gate 2 is open become candidates, so instances with closed SGs produce no noise.
- Every gate is evaluated and kept as evidence, even after one blocks, so the reader sees the whole picture.
- Any gate seen **BLOCKED** gives **NOT_EXPOSED**. A known block is enough, even if another gate's data is missing.
- No block, but a gate could not be evaluated, gives **UNKNOWN** (severity `UNVERIFIED`), naming the missing permission.
- All gates open gives **EXPOSED** (`HIGH`), with copy-paste remediation.
- A stopped instance with every network gate open is reported as `INFO`: it becomes exposed the moment it starts.

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

**Data in a real integration.** The fixtures are the exact output of `aws ec2 describe-instances` (etc.)
and decode straight into the `aws-sdk-go-v2` types. A live collector would call the same four APIs per
region with paginators (`ec2.NewDescribeInstancesPaginator`, …) under an assumed read-only role, and
write the same `Snapshot`. Nothing in the check changes.

**Existing tools considered.**
- *Prowler / ScoutSuite* flag "SG open to 0.0.0.0/0". That is the noisy signal this check refines. They could be used as candidate input.
- *VPC Reachability Analyzer* proves one source→destination path at a time and is priced per analysis, so it doesn't fit a sweep of every instance.
- *Network Access Analyzer* can express "internet → ENI" scopes and is a good **validation oracle** for this logic before production.
- I wrote the evaluation myself because the evidence trail and the UNKNOWN semantics are the product here, and because the same normalized snapshot feeds checks B and C.

**Code layout.**

```
cmd/scanner/                  CLI: flags, text/JSON output
internal/snapshot/            loads describe-*.json + errors.json into SDK types; tracks missing datasets
internal/exposure/            verdict: combines gate results into findings and remediation
internal/exposure/gates/      one file per AWS control; each returns OPEN / BLOCKED / UNKNOWN + evidence
fixtures/                     demo and missing-permission snapshots (see fixtures/README.md)
```

## 3. Assumptions

- "The internet" means an arbitrary IPv4 client. A rule counts only if its CIDR is `/0`.
- The instance's subnet is the primary network interface's subnet. Instances with several interfaces in different subnets are not modelled.
- An open path means exposed. Whether a process actually listens on the port is not visible from AWS APIs (see limits).
- One account, one region per snapshot.

## 4. Limits: what could change the conclusion

**Could make a NOT_EXPOSED instance actually exposed (false negatives):**
- **Load balancers:** an internet-facing ALB/NLB, CloudFront or Global Accelerator in front of a *private* instance. Check A only follows the direct path.
- **IPv6:** a `::/0` SG rule with a `::/0` route to the IGW. Out of scope here, but the same gate model applies.
- **Partial ranges:** an SG or NACL rule for a narrower but still public range (e.g. a `/8`), or SG rules via prefix lists. These are treated as not matching "an arbitrary client", which understates partial exposure.
- **Other attached ENIs**, in a public subnet, with their own public IP.

**Could make an EXPOSED instance actually safe (false positives):**
- A host firewall (iptables, Windows Firewall), or nothing listening on the port.
- AWS Network Firewall or a Gateway Load Balancer inspecting traffic via ingress routing on the IGW.
- Even when the port is reachable, key-only SSH or MFA lower the likelihood of compromise, but not the exposure.

**Time:** the result is a point-in-time snapshot. A rule added a minute later is not seen until the next scan.

**Missing data or permissions.** Absence of data is never treated as a pass:
- A denied API call (`UnauthorizedOperation`) is recorded in `errors.json`. Every gate that depends on it reports **UNKNOWN** with the exact missing action (`ec2:DescribeNetworkAcls`), the instance gets `UNVERIFIED` severity, and the report lists the data gap.
- A gate seen blocking still wins: no public IP is NOT_EXPOSED even when the NACLs are unknown.
- If `DescribeInstances` itself is missing, the scan of that account fails loudly instead of returning "0 findings".
- For a customer I would surface coverage separately: "N accounts or regions not fully scanned, because of X".

## 5. Production scale: 3,000 environments

**Onboarding and access.** Deploy one read-only role per account via CloudFormation StackSets from the
customer's AWS Organization. The scanner assumes it with `sts:AssumeRole` and an `ExternalId`, using
short-lived credentials and no stored keys.

**Work model.**
- One job per (account, region): 3,000 accounts × ~17 enabled regions ≈ 50k small jobs.
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

**Be incremental.** Use EventBridge or CloudTrail events (`AuthorizeSecurityGroupIngress`, `CreateRoute`,
`ReplaceNetworkAclEntry`, `AssociateAddress`, …) to rescan only the affected account and region within
minutes, and keep a periodic full scan as reconciliation. AWS Config aggregators are an alternative
inventory source.

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

1. Live collector (`-aws-profile`, `-region`) producing the same snapshot, with a Terraform lab to reproduce the demo cases in a real account.
2. Internet-facing ALB/NLB path and IPv6.
3. Check B on top of A: reachable instance × instance profile permissions gives a prioritised severity.
4. Group findings by root-cause security group.

## Bonus: Aikido scan

_TODO: connect a sandbox AWS account to Aikido, scan it, and compare Aikido's findings with this scanner's verdicts for the same resources._
