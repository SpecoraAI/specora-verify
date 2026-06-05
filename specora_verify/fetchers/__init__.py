"""Source fetchers for multi-surface mirror verification (PR-ENT-540).

Fetchers retrieve external anchors from different publication surfaces:
- GitHub Releases
- S3 versioned buckets
- DNS TXT records
- Local files (offline mode)
"""

from specora_verify.fetchers.dns import fetch_dns_txt_anchor
from specora_verify.fetchers.github import fetch_latest_github_anchor
from specora_verify.fetchers.local import load_local_anchor
from specora_verify.fetchers.s3 import fetch_latest_s3_anchor

__all__ = [
    "fetch_latest_github_anchor",
    "fetch_latest_s3_anchor",
    "fetch_dns_txt_anchor",
    "load_local_anchor",
]
