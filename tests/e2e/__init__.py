"""End-to-end test suites for specora-verify.

EPIC-B03: every test in this subpackage exercises the full out-of-band
pipeline — reader → canonicalizer → signer → on-disk bundle → verifier
— against a real on-disk fixture export. These tests are the contract
that keeps `specora-verify run` runnable for customers.
"""
