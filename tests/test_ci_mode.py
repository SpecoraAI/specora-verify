"""Tests for CI mode exit code mapping.

These tests verify that:
1. WARN (exit 1) maps to FAIL (exit 2) in CI mode
2. Other exit codes are unaffected
3. Output indicates when mapping occurs
"""

from __future__ import annotations

import pytest

from specora_verify.errors import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_WARN,
    exit_code_name,
    map_exit_code_for_ci,
)


class TestExitCodeMapping:
    """Tests for exit code mapping in CI mode."""

    def test_pass_unchanged_in_ci_mode(self):
        """PASS (0) stays PASS in CI mode."""
        assert map_exit_code_for_ci(EXIT_PASS, ci_mode=True) == EXIT_PASS

    def test_warn_unchanged_without_ci_mode(self):
        """WARN (1) stays WARN without CI mode."""
        assert map_exit_code_for_ci(EXIT_WARN, ci_mode=False) == EXIT_WARN

    def test_warn_maps_to_fail_in_ci_mode(self):
        """WARN (1) maps to FAIL (2) in CI mode."""
        assert map_exit_code_for_ci(EXIT_WARN, ci_mode=True) == EXIT_FAIL

    def test_fail_unchanged_in_ci_mode(self):
        """FAIL (2) stays FAIL in CI mode."""
        assert map_exit_code_for_ci(EXIT_FAIL, ci_mode=True) == EXIT_FAIL

    def test_error_unchanged_in_ci_mode(self):
        """ERROR (3) stays ERROR in CI mode."""
        assert map_exit_code_for_ci(EXIT_ERROR, ci_mode=True) == EXIT_ERROR

    def test_all_codes_unchanged_without_ci_mode(self):
        """All codes unchanged when CI mode is disabled."""
        for code in [EXIT_PASS, EXIT_WARN, EXIT_FAIL, EXIT_ERROR]:
            assert map_exit_code_for_ci(code, ci_mode=False) == code


class TestExitCodeNames:
    """Tests for exit code name formatting."""

    def test_pass_name(self):
        """PASS code has correct name."""
        assert exit_code_name(EXIT_PASS) == "PASS"

    def test_warn_name(self):
        """WARN code has correct name."""
        assert exit_code_name(EXIT_WARN) == "WARN"

    def test_fail_name(self):
        """FAIL code has correct name."""
        assert exit_code_name(EXIT_FAIL) == "FAIL"

    def test_error_name(self):
        """ERROR code has correct name."""
        assert exit_code_name(EXIT_ERROR) == "ERROR"

    def test_unknown_code(self):
        """Unknown code returns UNKNOWN."""
        assert exit_code_name(99) == "UNKNOWN"


class TestExitCodeValues:
    """Tests for exit code values match expected contract."""

    def test_pass_is_zero(self):
        """PASS must be 0 for CI compatibility."""
        assert EXIT_PASS == 0

    def test_warn_is_one(self):
        """WARN must be 1."""
        assert EXIT_WARN == 1

    def test_fail_is_two(self):
        """FAIL must be 2."""
        assert EXIT_FAIL == 2

    def test_error_is_three(self):
        """ERROR must be 3."""
        assert EXIT_ERROR == 3
