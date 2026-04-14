# Mirror Verification Test Fixtures

PR-ENT-540: Multi-Surface External Anchoring

## Fixtures

### valid-github.json
GitHub release anchor with full 64-character anchor_hash.

### valid-s3.json
S3 anchor with identical anchor_hash (should match GitHub).

### valid-dns.txt
DNS TXT record value with truncated 32-character hash prefix.
Format: `v=sa1;i={index};h={hash[:32]};t={unix_timestamp}`

### mismatch-s3.json
S3 anchor with different anchor_hash (should trigger INV-ANCHOR-009 violation).

## Test Scenarios

| Scenario | GitHub | S3 | DNS | Quorum | Expected Status |
|----------|--------|-----|-----|--------|-----------------|
| valid-multi-surface | valid-github.json | valid-s3.json | valid-dns.txt | 2 | PASS |
| hash-mismatch | valid-github.json | mismatch-s3.json | - | 2 | FAIL |
| partial-reachable | valid-github.json | valid-s3.json | (missing) | 2 | WARN |
| quorum-failure | valid-github.json | (missing) | (missing) | 2 | ERROR |
| dns-truncation | valid-github.json | (missing) | valid-dns.txt | 2 | PASS |

## Exit Codes

- 0: PASS - Quorum met, all sources agree
- 1: WARN - Quorum met, some sources unreachable
- 2: FAIL - Hash mismatch detected (INV-ANCHOR-009 violation)
- 3: ERROR - Unable to reach quorum
