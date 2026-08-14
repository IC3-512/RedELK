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
