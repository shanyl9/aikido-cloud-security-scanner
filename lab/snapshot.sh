#!/usr/bin/env bash
# Capture a live snapshot for the scanner, read-only.
# Runs the same four EC2 Describe* calls the fixtures come from and writes them in the
# same layout (describe-*.json). A call that fails (e.g. missing permission) is recorded
# in errors.json instead, so the scanner reports UNKNOWN rather than "safe".
#
# Usage: ./snapshot.sh <output-dir> [aws cli args, e.g. --region eu-central-1 --profile sandbox]
set -uo pipefail

out="${1:?usage: snapshot.sh <output-dir> [aws cli args]}"
shift
mkdir -p "$out"
errors=()

for pair in \
  "DescribeInstances:describe-instances" \
  "DescribeSecurityGroups:describe-security-groups" \
  "DescribeRouteTables:describe-route-tables" \
  "DescribeNetworkAcls:describe-network-acls"; do
  op="${pair%%:*}"
  cmd="${pair#*:}"
  file="$out/$cmd.json"
  if aws ec2 "$cmd" --output json "$@" >"$file" 2>"$file.err"; then
    echo "ok      $op"
    rm -f "$file.err"
  else
    code=$(grep -o 'An error occurred ([A-Za-z.]*)' "$file.err" | head -1 | sed 's/.*(\(.*\))/\1/')
    msg=$(tr '\n' ' ' <"$file.err" | sed 's/"/\\"/g')
    echo "FAILED  $op: ${code:-unknown error}"
    errors+=("{\"Operation\":\"$op\",\"Action\":\"ec2:$op\",\"Code\":\"${code:-Unknown}\",\"Message\":\"$msg\"}")
    rm -f "$file" "$file.err"
  fi
done

if ((${#errors[@]})); then
  (IFS=,; echo "{\"Errors\":[${errors[*]}]}") >"$out/errors.json"
fi
echo "snapshot written to $out"
