"""
Part of RedELK

Tests for the installer that ships inside every generated client package.

The regression that matters here: rsync was never installed on the C2 server. The cron file
stages artefacts with /usr/bin/rsync, rush.rc pins the same path, and the RedELK server's pull
re-executes it on this end - so a teamserver without the package looks perfectly healthy (cron
fires, ssh connects, filebeat ships its logs) while not one screenshot, download or credential
ever reaches Elasticsearch.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "redelk_setup" / "templates" / "client" / "install.py"


@pytest.fixture
def installer():
    """Import the installer by path; it is a package template, not an importable module."""
    spec = importlib.util.spec_from_file_location("redelk_client_install", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    del sys.modules[spec.name]


@pytest.fixture
def runner(installer):
    """A Runner that records commands instead of running them."""

    class Recorder(installer.Runner):
        def __init__(self, dry_run=False):
            super().__init__(dry_run)
            self.commands: list[list[str]] = []

        def run(self, argv, *, check=True, quiet=False):
            self.commands.append(argv)
            return 0

    return Recorder


@pytest.fixture
def bare_host(installer, monkeypatch):
    """A host with none of the binaries the sync needs on its PATH."""
    monkeypatch.setattr(installer.shutil, "which", lambda binary: None)


@pytest.fixture
def package(installer, monkeypatch, tmp_path):
    """The files install_sync() reads out of the package it was unpacked from."""
    here = tmp_path / "package"
    (here / "scripts").mkdir(parents=True)
    (here / "rush.rc").write_text("# rush.rc\n", encoding="utf-8")
    (here / "redelk_authorized_key.pub").write_text("ssh-rsa AAAAtest redelk\n", encoding="utf-8")
    (here / "redelk.cron").write_text("# cron\n", encoding="utf-8")
    monkeypatch.setattr(installer, "HERE", here)
    return here


def test_the_sync_install_provides_both_rush_and_rsync(installer, runner, bare_host, package):
    """rsync is not installed by default on a Debian teamserver, and nothing else pulls it in."""
    recorder = runner(dry_run=True)

    installer.install_sync(recorder, {"type": "sliver", "ssh_user": "scponly"})

    installs = [argv for argv in recorder.commands if argv[:3] == ["apt-get", "install", "-y"]]
    assert ["apt-get", "install", "-y", "rush"] in installs
    assert ["apt-get", "install", "-y", "rsync"] in installs


def test_an_unavailable_rsync_says_what_it_breaks(installer, runner, bare_host):
    """apt "succeeding" without providing rsync used to leave a bare 'command failed'."""
    recorder = runner()

    with pytest.raises(installer.InstallError) as raised:
        installer._ensure_rsync(recorder, "scponly")  # noqa: SLF001 - the helper under test

    message = str(raised.value)
    assert "apt-get install rsync" in message
    assert "collected" in message  # names the consequence, not just the failed command
    assert "run this installer again" in message


def test_a_dry_run_reports_the_install_instead_of_failing(installer, runner, bare_host):
    """--dry-run is what an operator uses to inspect an unprepared host."""
    recorder = runner(dry_run=True)

    installer._ensure_rsync(recorder, "scponly")  # noqa: SLF001 - the helper under test

    assert recorder.commands == [["apt-get", "install", "-y", "rsync"]]


def test_an_rsync_outside_the_pinned_path_is_called_out(installer, runner, monkeypatch, capsys):
    """rush.rc's `set[0]` and the cron file both name /usr/bin/rsync literally."""
    monkeypatch.setattr(installer.shutil, "which", lambda binary: "/opt/local/bin/rsync")
    recorder = runner()

    installer._ensure_rsync(recorder, "scponly")  # noqa: SLF001 - the helper under test

    assert recorder.commands == []
    assert installer.RSYNC_PATH in capsys.readouterr().out
