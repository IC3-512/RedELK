"""Outflank's task names are the only ATT&CK signal there is, so the table has to be right.

Outflank records no technique data: its task table has fifteen columns and none of them, nor any
column in any of its three databases, matches technique|mitre|attack|ttp. Cobalt Strike writes the
techniques into its beacon log and 51-filter-c2-cobaltstrike parses them out; for Outflank the task
name is all we have, so outflankstage1_task_to_ttp.rb maps it.

The script carries its own `test` blocks, which Logstash runs on every `logstash -t` - that is, on
every install rather than only in CI. What those cannot check is whether the table's *keys* are
real Outflank commands: a typo maps a command that will never arrive, and silently produces no
ATT&CK data for the command that does.
"""

from __future__ import annotations

import re

from conftest import REPO_ROOT

SCRIPT = (
    REPO_ROOT / "elkserver/mounts/logstash-config/redelk-main/scripts/outflankstage1_task_to_ttp.rb"
)
STAGE1_FILTER = (
    REPO_ROOT
    / "elkserver/mounts/logstash-config/redelk-main/conf.d/50-filter-c2-outflankstage1_logstash.conf"
)

# lib/outflank_stage1/outflank_stage1/task/tasks on a running Outflank server - one module per
# command. Hard-coded because the test cannot reach a teamserver; refresh it when Outflank ships
# new commands, and test_no_unknown_task_is_mapped will catch a rename.
OUTFLANK_TASKS = {
    "burn",
    "cat",
    "cd",
    "check_tcc",
    "config",
    "cp",
    "delay",
    "dnsname",
    "domainname",
    "download",
    "drives",
    "env",
    "exec_bof",
    "exec_bof_async",
    "exec_command",
    "exec_dotnet",
    "exec_jxa",
    "exec_process",
    "exec_shellcode",
    "exit",
    "fullcheckin",
    "getprivs",
    "getsystem",
    "help",
    "hooks",
    "ip",
    "kill",
    "link",
    "list_apps",
    "list_entitlements",
    "load_library",
    "ls",
    "make_token",
    "mkdir",
    "mv",
    "note",
    "plist",
    "portforward",
    "ps",
    "psgrep",
    "psx",
    "psxx",
    "pwd",
    "reg",
    "rev2self",
    "rm",
    "rmdir",
    "rportforward",
    "screenshot",
    "sleep",
    "socks",
    "spawnas",
    "steal_token",
    "task",
    "timestomp",
    "unlink",
    "upload",
    "uptime",
    "whoami",
}

ENTRY = re.compile(r'^\s*"([a-z0-9_]+)"\s*=>\s*\[([^\]]*)\]', re.MULTILINE)


def mapping() -> dict[str, list[str]]:
    """The table as {task: [technique ids]}, parsed out of the Ruby source."""
    table = SCRIPT.read_text(encoding="utf-8").split("TASK_TECHNIQUES = {", 1)[1]
    table = table.split("}.freeze", 1)[0]
    return {task: re.findall(r'"([^"]+)"', ids) for task, ids in ENTRY.findall(table)}


def test_the_table_parses_and_is_not_trivially_small():
    assert len(mapping()) >= 40


def test_every_technique_id_is_well_formed():
    """A malformed id silently produces no ATT&CK object: enrich_ttp cannot resolve it and
    mitre_make_technique_references skips anything that is not T#### or T####.###."""
    for task, ids in mapping().items():
        assert ids, f"{task} maps to an empty list"
        for technique in ids:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique), f"{task} -> {technique!r}"


def test_no_unknown_task_is_mapped():
    """A typo here is invisible in production - the entry simply never matches anything."""
    unknown = set(mapping()) - OUTFLANK_TASKS
    assert not unknown, f"not Outflank commands: {sorted(unknown)}"


def test_the_commands_an_operator_actually_runs_are_covered():
    """Taken from a real engagement's rtops index rather than chosen to make the test pass."""
    observed = {"ls", "screenshot", "whoami", "psx", "download"}
    missing = observed - set(mapping())
    assert not missing, f"unmapped despite being run on a live engagement: {sorted(missing)}"


def test_navigation_and_housekeeping_stay_unmapped():
    """A plausible-but-wrong technique is worse than a gap - the gap is visible in a Navigator
    layer and the wrong one is not. These have no ATT&CK meaning and must not acquire one."""
    table = mapping()
    for task in ("cd", "pwd", "mkdir", "mv", "cp", "sleep", "delay", "exit", "help", "note"):
        assert task not in table, f"{task} was given a technique it does not perform"


def test_a_task_that_does_two_things_gets_both_techniques():
    assert mapping()["download"] == ["T1005", "T1041"]


def test_the_script_is_wired_into_the_filter():
    """The table is inert unless the filter calls it, and unless the reference builder runs after."""
    source = STAGE1_FILTER.read_text(encoding="utf-8")
    assert "outflankstage1_task_to_ttp.rb" in source
    assert "mitre_make_technique_references.rb" in source
    assert source.index("outflankstage1_task_to_ttp.rb") < source.index(
        "mitre_make_technique_references.rb"
    ), "references are built from the ids, so the mapping has to run first"
