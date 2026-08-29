#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'usage: run-fixture.sh ARTIFACT_DIRECTORY' >&2
  exit 2
fi

fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
artifact_dir=$1
input_sha256=$(sha256sum "$fixture_dir/input.txt" | awk '{print $1}')
expected_input_sha256=967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6

if [ "$input_sha256" != "$expected_input_sha256" ]; then
  printf '%s\n' 'fixture input digest mismatch' >&2
  exit 1
fi

mkdir -p "$artifact_dir"
printf '%s\n' '{"fixture_version":"v1","input_sha256":"967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6"}' > "$artifact_dir/result.json"
printf '%s\n' 'fixture=buzz-ci-capacity-one-v1 input_sha256=967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6 artifact=result.json'
