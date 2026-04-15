# CloudTrail reader — no test keys required

AWS CloudTrail has no per-event signatures. Integrity is anchored
at the CloudTrail log file validation level (signed digest files
emitted periodically by CloudTrail itself).

The CloudTrail reader therefore accepts `--public-key` only for
interface compatibility with other readers and ignores it. This
directory exists so the fixture tree structurally matches the
Anthropic reader fixture layout.
