"""Audit-chain verification reads are bounded before row validation begins."""

from uuid import uuid4

import pytest

from dlp_platform.audit.service import AuditService, AuditVerificationLimitError


class FakeMappings:
    def all(self):
        return [object(), object(), object(), object()]


class FakeResult:
    def mappings(self):
        return FakeMappings()


class FakeSession:
    statement = None

    def execute(self, statement):
        self.statement = statement
        return FakeResult()


def test_audit_chain_verification_queries_only_one_beyond_limit():
    session = FakeSession()
    with pytest.raises(AuditVerificationLimitError):
        AuditService().verify_chain_result(session, uuid4(), max_events=3)

    assert session.statement is not None
    assert session.statement._limit_clause.value == 4
