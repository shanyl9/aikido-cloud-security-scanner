# Live lab

Reproduces the demo cases with real AWS resources, so the scanner (and Aikido) can be run against a
real account. Use a **personal sandbox account**, never a work account.

All instances share one security group that allows tcp/22 from `0.0.0.0/0`. No key pair is attached,
so nobody can log in. Cost is a few cents per hour: delete the stack the same day.

| Instance (Name tag) | What blocks it | Expected verdict |
|---|---|---|
| `lab-exposed` | nothing | **EXPOSED** |
| `lab-no-public-ip` | no public IP | NOT_EXPOSED (public-ip) |
| `lab-main-rt-no-igw` | subnet has no route table of its own; the VPC main table has only the local route | NOT_EXPOSED (route-table) |
| `lab-nacl-deny` | NACL rule 90 denies tcp/22 before rule 100 allows all | NOT_EXPOSED (nacl-inbound) |
| `lab-nacl-no-ephemeral` | NACL allows 22 in, only 443 out | NOT_EXPOSED (nacl-outbound) |
| `lab-orphan-all-open` (SG) | attached to nothing | no finding |

## Steps (AWS CloudShell)

Open CloudShell (the `>_` icon in the console's top bar) in the region you want to use.

**1. Upload the two files.** In CloudShell: **Actions → Upload file**, once for `exposure-lab.yaml` and
once for `snapshot.sh`.

**2. Deploy the lab** (about 3 minutes):

```bash
aws cloudformation deploy --template-file exposure-lab.yaml --stack-name exposure-lab
aws cloudformation describe-stacks --stack-name exposure-lab --query 'Stacks[0].Outputs' --output table
```

If `t3.micro` is not available in the region, add `--parameter-overrides InstanceType=t2.micro`.

**3. Connect Aikido and let it scan.** In Aikido: **Connect cloud → AWS** and follow the wizard (it
deploys a read-only role via CloudFormation). Wait until the cloud scan finishes.

**4. Capture a snapshot for this scanner** (read-only `Describe*` calls):

```bash
bash snapshot.sh lab-snapshot
tar czf lab-snapshot.tgz lab-snapshot
```

Then **Actions → Download file** → `lab-snapshot.tgz`.

**5. Run the scanner locally** on the downloaded snapshot:

```bash
mkdir -p snapshots && tar xzf ~/Downloads/lab-snapshot.tgz -C snapshots
go run ./cmd/scanner -snapshot snapshots/lab-snapshot
```

**6. Delete the lab** when done:

```bash
aws cloudformation delete-stack --stack-name exposure-lab
```
