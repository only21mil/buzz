# Buzz CI workflow schema

`buzz-ci-workflow` parses the static job policy that the broker copies into its
signed manifest. Workflow bytes keep their GitHub Actions shape. The only Buzz
job extension in this version is `required`, which defaults to `true`.

The job-level `required` field is the sole in-file source of required-job
policy. A top-level `manifest` block is rejected. Accepting
`manifest.required_jobs` would create two policy sources whose disagreement
could change the broker verdict. The broker signs the parsed `required` value
and the derived `skip_policy` for each job instead. `skip_policy` is `allow`
when the job has an `if` key or sets `required: false`; otherwise it is
`forbid`.

The parser hashes the original bytes without normalizing or reserializing them.
It accepts ordinary GitHub Actions fields that do not affect the static Buzz
manifest. It rejects malformed Buzz policy, duplicate or non-static job IDs,
invalid dependency references, and workflows larger than 128 KiB.
