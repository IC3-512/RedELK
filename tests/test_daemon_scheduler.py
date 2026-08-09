"""
Part of RedELK

The scheduler loop in daemon.py.

daemon.py used to be a `* * * * *` cron entry, which put a one-minute floor under every alarm
however short its interval was. For an implant check-in that is the difference between an operator
reacting while somebody is still at the machine and reacting once they have gone. It now schedules
itself, so what is tested here is the behaviour that made cron safe and has to be preserved without
it: a pass that raises must not kill the loop, a slow pass must not be silently swallowed, and a
signal has to stop it.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import signal

import pytest


@pytest.fixture
def daemon(daemon_env):
    return daemon_env({"interval": 5}).import_daemon()


def test_the_tick_comes_from_the_config(daemon_env):
    """modules.interval is the scheduler tick - the floor under every alarm's latency."""
    assert daemon_env({"interval": 5}).import_daemon().INTERVAL == 5
    assert daemon_env({"interval": 30}).import_daemon().INTERVAL == 30


def test_a_pass_that_raises_does_not_stop_the_scheduler(daemon, monkeypatch, caplog):
    """The whole point of a long-lived loop is that it is still there on the next tick.

    Under cron a crash cost one minute. A crash that escaped the loop would cost every alarm from
    then on, and the container would still look healthy.
    """
    calls = []

    def exploding_pass(_modules=None):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("elasticsearch went away")
        return 0

    monkeypatch.setattr(daemon, "run_once", exploding_pass)
    monkeypatch.setattr(daemon, "load_modules", lambda: ({}, {}, {}))

    # Stop after the second pass, which only happens if the first one did not kill the loop.
    real_wait = daemon.threading.Event.wait

    def wait_then_stop(self, timeout=None):
        if len(calls) >= 2:
            self.set()
        return real_wait(self, 0)

    monkeypatch.setattr(daemon.threading.Event, "wait", wait_then_stop)
    daemon.run_forever(tick=0)

    assert len(calls) >= 2, "the scheduler stopped after the failing pass"
    assert "unhandled error" in caplog.text.lower()


def test_a_pass_slower_than_the_tick_is_reported(daemon, monkeypatch, caplog):
    """Otherwise the configured tick silently is not the latency the operator gets."""
    clock = iter([0.0, 30.0, 30.0, 30.0])
    monkeypatch.setattr(daemon.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(daemon, "run_once", lambda _modules=None: 0)
    monkeypatch.setattr(daemon, "load_modules", lambda: ({}, {}, {}))

    def stop_immediately(self, timeout=None):
        self.set()
        return True

    monkeypatch.setattr(daemon.threading.Event, "wait", stop_immediately)
    daemon.run_forever(tick=5)

    assert "running behind" in caplog.text


def test_sigterm_stops_the_loop(daemon, monkeypatch):
    """docker stop has to end the container, not wait out the timeout and get SIGKILL."""
    monkeypatch.setattr(daemon, "load_modules", lambda: ({}, {}, {}))

    def one_pass(_modules=None):
        # Whatever the entrypoint's signal handler is, delivering it must set the stop flag.
        signal.raise_signal(signal.SIGTERM)
        return 0

    monkeypatch.setattr(daemon, "run_once", one_pass)
    assert daemon.run_forever(tick=0) == 0


def test_modules_are_imported_once_not_every_tick(daemon, monkeypatch):
    """Re-importing every module on a 5-second tick would be the loop's whole cost."""
    loads = []
    monkeypatch.setattr(daemon, "load_modules", lambda: (loads.append(1), ({}, {}, {}))[1])

    passes = []

    def counting_pass(modules=None):
        passes.append(modules)
        return 0

    monkeypatch.setattr(daemon, "run_once", counting_pass)

    def stop_after_three(self, timeout=None):
        if len(passes) >= 3:
            self.set()
        return True

    monkeypatch.setattr(daemon.threading.Event, "wait", stop_after_three)
    daemon.run_forever(tick=0)

    assert len(loads) == 1, f"load_modules ran {len(loads)} times"
    assert len(passes) >= 3


def test_once_runs_a_single_pass(daemon, monkeypatch):
    """--once is what a cron-driven deployment and a debugging operator still use."""
    passes = []
    monkeypatch.setattr(daemon, "run_once", lambda _modules=None: (passes.append(1), 0)[1])
    monkeypatch.setattr(daemon, "acquire_lock", lambda: object())
    monkeypatch.setattr(daemon, "setup_logging", lambda: None)

    assert daemon.main(["--once"]) == 0
    assert len(passes) == 1


def test_a_second_daemon_does_not_start(daemon, monkeypatch):
    """Two schedulers would double every notification."""
    monkeypatch.setattr(daemon, "acquire_lock", lambda: None)
    monkeypatch.setattr(daemon, "setup_logging", lambda: None)
    monkeypatch.setattr(
        daemon, "run_forever", lambda tick: pytest.fail("a second daemon started scheduling")
    )

    assert daemon.main([]) == 0
