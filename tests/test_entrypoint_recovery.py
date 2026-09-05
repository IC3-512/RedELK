"""The base container must fail closed when provisioning does not complete."""

from __future__ import annotations

import sys

import pytest

from conftest import DAEMON_SCRIPTS_DIR

sys.path.insert(0, str(DAEMON_SCRIPTS_DIR))

import entrypoint  # noqa: E402


class FinishedProcess:
    def __init__(self, returncode: int):
        self.returncode = returncode

    def poll(self) -> int:
        return self.returncode


def test_failed_bootstrap_becomes_a_failed_container(monkeypatch, tmp_path):
    monkeypatch.setattr(entrypoint, "ES_MARKER", tmp_path / "es-provisioned")

    result = entrypoint.wait_for_provisioning(FinishedProcess(1))

    assert result == 1


def test_existing_es_marker_does_not_hide_a_later_kibana_failure(monkeypatch, tmp_path):
    marker = tmp_path / "es-provisioned"
    marker.touch()
    monkeypatch.setattr(entrypoint, "ES_MARKER", marker)

    result = entrypoint.wait_for_provisioning(FinishedProcess(2))

    assert result == 2


def test_success_requires_both_a_zero_exit_and_the_es_marker(monkeypatch, tmp_path):
    marker = tmp_path / "es-provisioned"
    monkeypatch.setattr(entrypoint, "ES_MARKER", marker)

    assert entrypoint.wait_for_provisioning(FinishedProcess(0)) == 1

    marker.touch()
    assert entrypoint.wait_for_provisioning(FinishedProcess(0)) == 0


def test_main_does_not_start_scheduled_work_after_failed_provisioning(monkeypatch):
    events: list[str] = []
    process = FinishedProcess(1)
    monkeypatch.setattr(entrypoint, "fix_permissions", lambda: events.append("permissions"))
    monkeypatch.setattr(entrypoint, "start_bootstrap", lambda: process)
    monkeypatch.setattr(entrypoint, "wait_for_provisioning", lambda candidate: 1)
    monkeypatch.setattr(entrypoint, "start_cron", lambda: events.append("cron"))
    monkeypatch.setattr(
        entrypoint.os,
        "execvp",
        lambda *_: pytest.fail("the daemon must not start after failed provisioning"),
    )

    assert entrypoint.main() == 1
    assert events == ["permissions"]


def test_main_starts_cron_and_daemon_only_after_success(monkeypatch):
    events: list[str] = []
    process = FinishedProcess(0)
    monkeypatch.setattr(entrypoint, "fix_permissions", lambda: events.append("permissions"))
    monkeypatch.setattr(entrypoint, "start_bootstrap", lambda: process)

    def wait_for(candidate):
        assert candidate is process
        events.append("provisioned")
        return 0

    def execvp(*_):
        events.append("daemon")
        raise RuntimeError("exec intercepted")

    monkeypatch.setattr(entrypoint, "wait_for_provisioning", wait_for)
    monkeypatch.setattr(entrypoint, "start_cron", lambda: events.append("cron"))
    monkeypatch.setattr(entrypoint.os, "execvp", execvp)

    with pytest.raises(RuntimeError, match="exec intercepted"):
        entrypoint.main()

    assert events == ["permissions", "provisioned", "cron", "daemon"]
