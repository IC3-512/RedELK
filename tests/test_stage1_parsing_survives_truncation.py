"""A truncated task output must cost the output, not the whole document.

Filebeat joins a Stage1 task's multi-line output into one event and, with no max_lines set, cut it
at its default of 500 lines. That took the trailing ';' with it, and the Logstash grok ended with a
greedy multi-line group followed by a literal ';' - so on a truncated line the engine backtracked
across the whole body hunting for a terminator that was not there and hit the grok timeout.

A grok that times out sets *nothing*, so the damage was not limited to the output: implant.id,
implant.task, implant.task_id, implant.task_parameters and c2.operator were all missing too. On a
real engagement two of seventeen rtops documents were lost that way, and they were the two largest
outputs - `ls C:\\Windows\\System32` and `psx`. The commands most worth reading were exactly the
ones that arrived empty.

Reproduced against the stack's own Logstash before fixing. Both patterns on the same 500-line
truncated event:

    tags => ["multiline", "_OLD_TIMED_OUT"]      # old: no fields at all
    new  => {operator "dev", task_id "TESTTASK01", task "ls", id "TEST0001", output_len 18387}
"""

from __future__ import annotations

import re

from conftest import REPO_ROOT

STAGE1_FILTER = (
    REPO_ROOT
    / "elkserver/mounts/logstash-config/redelk-main/conf.d/50-filter-c2-outflankstage1_logstash.conf"
)
FILEBEAT_INPUT = REPO_ROOT / "tools/redelk_setup/templates/filebeat/inputs/outflankstage1.yml.j2"


def taskresponse_pattern() -> str:
    """The TASKRESPONSE grok pattern out of the filter."""
    for line in STAGE1_FILTER.read_text(encoding="utf-8").splitlines():
        if "TASKRESPONSE stage1Uid" in line and "match =>" in line:
            return line
    raise AssertionError("the TASKRESPONSE grok is gone")


def test_the_output_capture_does_not_require_a_terminator():
    """This is the whole bug: a ';' after the greedy group turns a truncated line into a timeout,
    and a timeout discards every field the pattern would have set, not just the output."""
    pattern = taskresponse_pattern()
    tail = pattern.split("taskResponse", 1)[1]
    assert not re.search(r'\)\}?"?\s*;', tail.replace(" ", "")), (
        "the output capture is followed by a required ';' again"
    )


def test_the_output_capture_is_a_character_class_not_an_alternation():
    """(.|\\r|\\n)* re-decides per character and gives the engine a backtrack point for each one.
    A single character class has neither property."""
    pattern = taskresponse_pattern()
    assert "[\\s\\S]*" in pattern
    assert "(.|\\r|\\n)*" not in pattern


def test_a_trailing_semicolon_is_still_stripped_from_the_output():
    """Dropping it from the pattern means a well-formed line now keeps the ';' the old pattern
    excluded, so it has to come off somewhere."""
    source = STAGE1_FILTER.read_text(encoding="utf-8")
    assert 'gsub => [ "[implant][output]", ";[\\s]*$", "" ]' in source


def test_the_filebeat_input_raises_max_lines():
    """Without this the truncation happens in the first place. The Cobalt Strike input has always
    set it; this one never did, which is why only Outflank lost documents."""
    source = FILEBEAT_INPUT.read_text(encoding="utf-8")
    match = re.search(r"max_lines:\s*(\d+)", source)
    assert match, "no max_lines, so Filebeat's default of 500 applies"
    assert int(match.group(1)) >= 100000


def test_stage1_matches_what_cobaltstrike_already_did():
    """The two inputs shipped different truncation behaviour for no reason anyone recorded."""
    cs = (REPO_ROOT / "tools/redelk_setup/templates/filebeat/inputs/cobaltstrike.yml.j2").read_text(
        encoding="utf-8"
    )
    stage1 = FILEBEAT_INPUT.read_text(encoding="utf-8")
    cs_limits = {int(v) for v in re.findall(r"max_lines:\s*(\d+)", cs)}
    stage1_limits = {int(v) for v in re.findall(r"max_lines:\s*(\d+)", stage1)}
    assert stage1_limits and stage1_limits <= cs_limits


def test_a_failed_download_does_not_become_a_download_record():
    """`Downloaded [Error 3] ...` matched the old test, so a download that never happened produced
    a downloads document that then failed its own grok - no path, no size, no local id to find."""
    source = STAGE1_FILTER.read_text(encoding="utf-8")
    assert r"Downloaded [^\[]/" in source, "the clone still fires on a failed download"


def test_the_star_separator_is_optional():
    """Stage1 does not write "*** " on every line - "UTC Unknown download for task X" has none -
    and requiring it turned a partial parse into no parse at all."""
    source = STAGE1_FILTER.read_text(encoding="utf-8")
    assert r"UTC (\*\*\* )?" in source


def test_host_os_type_is_mapped_as_a_keyword():
    """The filter derives host.os.type, and an unmapped field lands in a dynamic text field:
    Kibana cannot aggregate on it ("Fielddata is disabled on [host.os.type]"), so the value is
    there but no dashboard can group by it. ECS defines it, the template just never listed it."""
    import json

    template = json.loads(
        (
            REPO_ROOT
            / "elkserver/docker/redelk-base/redelkinstalldata/templates/component/redelk-ecs-base.json"
        ).read_text(encoding="utf-8")
    )

    def find_host_os(node, parent=""):
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict) and "os" in props and parent == "host":
                return props["os"]["properties"]
            for key, value in node.items():
                hit = find_host_os(
                    value, key if key not in ("properties", "mappings", "template") else parent
                )
                if hit is not None:
                    return hit
        return None

    host_os = find_host_os(template)
    assert host_os is not None, "host.os is not in the ECS component template at all"
    assert host_os.get("type", {}).get("type") == "keyword"


def test_an_argument_containing_a_semicolon_does_not_erase_the_command():
    """rtops is the record of what an operator did, and a semicolon used to remove a line from it.

    Stage1's format is "key:value; " delimited with no escaping, and every field was captured with
    [^;]*. An argument containing a semicolon ended the capture early, the rest of the line then
    matched nothing, and the whole grok failed - so the document arrived with no implant.task, no
    task_id and no operator. Confirmed on a live engagement: `ls C:\\a;b;c` was simply not in the
    audit record.

    No malice needed - Windows command lines and PATH-like arguments contain semicolons routinely -
    but malice is available: anyone who wants a command left out of the record only has to include
    one. Anchoring each capture on the key that follows it keeps the argument whole.
    """
    pattern = taskresponse_pattern()
    argument = pattern.split("taskRequestparameters")[1].split("taskResponse")[0]
    assert "[^;]*" not in argument, "the argument capture stops at the first semicolon again"
    assert "[\\s\\S]*?" in argument, "it should run to the key that follows it, lazily"


def test_the_argument_capture_is_anchored_on_the_next_key():
    """Lazy matching alone is not enough; it has to stop at something. `; taskResponse:` is the
    only reliable terminator, since the argument itself may contain anything."""
    assert "; taskResponse" in taskresponse_pattern()
