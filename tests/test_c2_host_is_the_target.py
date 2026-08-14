"""host.* on a C2 log document has to describe the target, never the teamserver.

Filebeat's add_host_metadata processor stamps the machine it runs on - the teamserver - onto every
line it ships. Both C2 filters tried to undo that with

    if [agent][name] == [host][name] { remove_field => [ "[host][name]" ] }

which only fires when Filebeat's agent.name happens to equal the machine's hostname. A deployment
that names its agents after their role (agent.name "outflank-init" on a host called "ip-10-0-1-84")
never satisfies it, and the values below are what that produced on a live deployment: 15 of 17
rtops documents attributed the implant's activity to the C2 server, and implantsdb held a Windows 11
implant with os.family "debian", os.codename "bookworm" and os.type "linux".
"""

from __future__ import annotations

import pytest

from conftest import REPO_ROOT

CONF_DIR = REPO_ROOT / "elkserver/mounts/logstash-config/redelk-main/conf.d"
STAGE1 = CONF_DIR / "50-filter-c2-outflankstage1_logstash.conf"
COBALT = CONF_DIR / "51-filter-c2-cobaltstrike_logstash.conf"

# Copied from a real deployment rather than invented, so the test fails the way production did.
TEAMSERVER_HOST = {
    "name": "ip-10-0-1-84",
    "hostname": "ip-10-0-1-84",
    "id": "ec274765cf1543db570ed88ca1f5e13e",
    "architecture": "x86_64",
    "containerized": False,
    "os": {
        "name": "Debian GNU/Linux",
        "family": "debian",
        "platform": "debian",
        "version": "12 (bookworm)",
        "kernel": "6.1.0-23-cloud-amd64",
        "codename": "bookworm",
        "type": "linux",
    },
}

IMPLANT_HOST = {
    "name": "DESKTOP-HP4RTL2",
    "os": {"name": "Windows", "version": "11.0", "kernel": "26100", "type": "windows"},
    "ip_int": "0.0.0.0",
    "ip_ext": "0.0.0.0",
}


@pytest.fixture
def enrich_stage1(daemon_env):
    daemon_env({})
    from modules.enrich_stage1 import module

    return module


# ------------------------------------------------------------------------------------------------
# the Logstash side: the teamserver's identity never reaches a document
# ------------------------------------------------------------------------------------------------


def code_of(path) -> str:
    """The file with its comments stripped.

    Both filters explain the removed guard in a comment that quotes it, so a naive substring check
    matches the explanation and reports the bug as still present.
    """
    return "\n".join(
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


@pytest.mark.parametrize("path", [STAGE1, COBALT], ids=["outflank-stage1", "cobaltstrike"])
def test_the_guard_that_never_fired_is_gone(path):
    source = code_of(path)
    assert "[agent][name] == [host][name]" not in source, (
        "this comparison silently does nothing whenever Filebeat's agent.name is not the machine's "
        "hostname, which is every deployment that names agents after their role"
    )


@pytest.mark.parametrize("path", [STAGE1, COBALT], ids=["outflank-stage1", "cobaltstrike"])
def test_the_whole_teamserver_host_is_removed_not_just_its_name(path):
    """Removing host.name alone leaves the mixed document: Windows name, debian family, linux type.

    host.os has to go as a subtree - listing individual os fields is how the original overwrite
    list ended up covering name, version and kernel but not family, platform, codename or type.
    """
    source = path.read_text(encoding="utf-8")
    for field in ("[host][name]", "[host][hostname]", "[host][id]", "[host][os]"):
        assert f'"{field}"' in source, f"{field} is still Filebeat's teamserver value"


def test_stage1_derives_an_os_type_from_what_the_implant_reported():
    """Stage1 reports a product name, not an ECS os type, so nothing fills host.os.type."""
    source = STAGE1.read_text(encoding="utf-8")
    assert '"[host][os][type]" => "windows"' in source
    assert "[host][os][name] =~" in source


# ------------------------------------------------------------------------------------------------
# the enrichment side: why removing it is what makes the implant's host land
# ------------------------------------------------------------------------------------------------


def test_the_implant_host_cannot_land_while_filebeat_metadata_is_there(enrich_stage1):
    """The mechanism behind the bug, kept as a test so the reasoning is not lost.

    enrich_stage1 copies the initial implant line's context onto every later line of that implant,
    but deliberately lets the destination win a conflict - an enrichment must not undo what another
    module wrote. That rule is right, and it is exactly why the fix belongs in Logstash: as long as
    Filebeat's teamserver value occupies host.name, the implant's real host can never replace it.
    """
    task_line = {"host": dict(TEAMSERVER_HOST), "implant": {"id": "Y5Y00AIR"}}
    initial_line = {"host": dict(IMPLANT_HOST), "implant": {"id": "Y5Y00AIR"}}

    partial = enrich_stage1.build_partial(initial_line, task_line)

    assert partial["host"]["name"] == "ip-10-0-1-84"
    assert partial["host"]["os"]["type"] == "linux"


def test_the_implant_host_lands_once_the_teamserver_metadata_is_removed(enrich_stage1):
    """What the Logstash change buys: the task line ends up describing the machine it happened on."""
    task_line = {"implant": {"id": "Y5Y00AIR"}}
    initial_line = {"host": dict(IMPLANT_HOST), "implant": {"id": "Y5Y00AIR"}}

    partial = enrich_stage1.build_partial(initial_line, task_line)

    assert partial["host"]["name"] == "DESKTOP-HP4RTL2"
    assert partial["host"]["os"]["name"] == "Windows"
    assert partial["host"]["os"]["type"] == "windows"
    assert "debian" not in str(partial["host"]), "no part of the teamserver may survive"


def test_a_windows_implant_never_comes_out_as_os_type_linux(enrich_stage1):
    """The shape that made the data unusable: host.os.name:Windows found it, host.os.type:windows
    did not, because the two came from different machines."""
    initial_line = {"host": dict(IMPLANT_HOST)}

    merged = enrich_stage1.build_partial(initial_line, {})["host"]

    assert not (merged["os"]["name"].startswith("Windows") and merged["os"]["type"] != "windows")
