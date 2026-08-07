"""
Part of RedELK

daemon.load_modules() and the module contract.

Modules are third-party-ish code: operators write their own alarms, and a module that fails to
import - a missing dependency, a syntax error after an edit on the server - must cost exactly one
module, not the whole run. Before v3 an import error took down alarming entirely.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import ast
import sys

import pytest

from conftest import DAEMON_SCRIPTS_DIR

GOOD_MODULE = '''
"""A well behaved enrichment module."""
info = {
    "version": 1.0,
    "name": "test good",
    "alarmmsg": "nothing",
    "description": "a module that imports cleanly",
    "type": "redelk_enrich",
    "submodule": "enrich_good",
}


class Module:
    def run(self):
        return {"hits": {"hits": [], "total": 0}}
'''

BROKEN_MODULE = '''
"""Raises while being imported, the way a missing dependency does."""
raise ImportError("No module named 'somethingelse'")
'''

SYNTAX_ERROR_MODULE = "def run(:\n"

NOT_A_MODULE = '''
"""A helper package that happens to live under modules/."""
HELPERS = 1
'''

UNKNOWN_TYPE_MODULE = """
info = {"type": "redelk_telepathy", "submodule": "telepathy"}


class Module:
    def run(self):
        return {}
"""

ALARM_MODULE = """
info = {
    "version": 1.0,
    "name": "test alarm",
    "alarmmsg": "something happened",
    "description": "an alarm",
    "type": "redelk_alarm",
    "submodule": "alarm_test",
}


class Module:
    def run(self):
        return {"hits": {"hits": [], "total": 0}}
"""

CONNECTOR_MODULE = """
info = {
    "version": 1.0,
    "name": "test connector",
    "alarmmsg": "",
    "description": "a connector",
    "type": "redelk_connector",
    "submodule": "connector_test",
}


class Module:
    def send_alarm(self, result):
        return True
"""


@pytest.fixture
def module_tree(tmp_path, daemon_env):
    """A directory of fake modules, wired into the daemon's `modules` package.

    daemon.py discovers modules by listing MODULES_PATH and importing `modules.<name>.module`,
    so the temporary directory is appended to the real package's __path__ and MODULES_PATH is
    pointed at it.
    """
    env = daemon_env({})
    daemon = env.import_daemon()

    root = tmp_path / "fake_modules"
    root.mkdir()

    import modules as modules_package

    original_path = list(modules_package.__path__)
    modules_package.__path__.append(str(root))
    imported_before = set(sys.modules)

    def add(name: str, source: str) -> None:
        directory = root / name
        directory.mkdir()
        (directory / "__init__.py").write_text("", encoding="utf-8")
        (directory / "module.py").write_text(source, encoding="utf-8")

    yield daemon, root, add

    modules_package.__path__[:] = original_path
    for name in set(sys.modules) - imported_before:
        del sys.modules[name]


def test_load_modules_sorts_modules_by_the_type_they_declare(module_tree, monkeypatch):
    daemon, root, add = module_tree
    add("enrich_good", GOOD_MODULE)
    add("alarm_test", ALARM_MODULE)
    add("connector_test", CONNECTOR_MODULE)
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    alarms, connectors, enrichments = daemon.load_modules()

    assert set(alarms) == {"alarm_test"}
    assert set(connectors) == {"connector_test"}
    assert set(enrichments) == {"enrich_good"}
    assert enrichments["enrich_good"]["status"] == "pending"
    assert enrichments["enrich_good"]["info"]["submodule"] == "enrich_good"


def test_a_module_that_raises_on_import_does_not_stop_the_others(module_tree, monkeypatch, caplog):
    """One broken module used to take down the whole daemon run."""
    daemon, root, add = module_tree
    add("enrich_broken", BROKEN_MODULE)
    add("enrich_good", GOOD_MODULE)
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    alarms, connectors, enrichments = daemon.load_modules()

    assert set(enrichments) == {"enrich_good"}
    assert "enrich_broken" not in enrichments
    assert alarms == {} and connectors == {}
    assert any("enrich_broken" in record.getMessage() for record in caplog.records)


def test_a_module_with_a_syntax_error_is_skipped(module_tree, monkeypatch):
    daemon, root, add = module_tree
    add("enrich_syntax", SYNTAX_ERROR_MODULE)
    add("enrich_good", GOOD_MODULE)
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    _, _, enrichments = daemon.load_modules()

    assert set(enrichments) == {"enrich_good"}


def test_a_directory_that_is_not_a_module_is_ignored(module_tree, monkeypatch):
    daemon, root, add = module_tree
    add("helpers_pkg", NOT_A_MODULE)
    add("enrich_good", GOOD_MODULE)
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    alarms, connectors, enrichments = daemon.load_modules()

    assert set(enrichments) == {"enrich_good"}
    assert alarms == {} and connectors == {}


def test_an_unknown_module_type_is_ignored(module_tree, monkeypatch):
    daemon, root, add = module_tree
    add("enrich_weird", UNKNOWN_TYPE_MODULE)
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    alarms, connectors, enrichments = daemon.load_modules()

    assert alarms == {} and connectors == {} and enrichments == {}


def test_loose_files_and_pycache_are_skipped(module_tree, monkeypatch):
    daemon, root, add = module_tree
    add("enrich_good", GOOD_MODULE)
    (root / "helpers.py").write_text("HELPERS = 1\n", encoding="utf-8")
    (root / "__pycache__").mkdir()
    monkeypatch.setattr(daemon, "MODULES_PATH", root)

    _, _, enrichments = daemon.load_modules()

    assert set(enrichments) == {"enrich_good"}


def test_a_missing_module_directory_is_reported_not_fatal(module_tree, monkeypatch, tmp_path):
    daemon, _, _ = module_tree
    monkeypatch.setattr(daemon, "MODULES_PATH", tmp_path / "does-not-exist")

    assert daemon.load_modules() == ({}, {}, {})


# ------------------------------------------------------------------------------------------------
# The shipped modules
# ------------------------------------------------------------------------------------------------

SHIPPED_DIRECTORIES = sorted(
    path
    for path in (DAEMON_SCRIPTS_DIR / "modules").iterdir()
    if path.is_dir() and path.name != "__pycache__"
)


def literal_info(path):
    """Read the module's `info` dict without importing it (which would need every dependency)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "info" for target in node.targets
        ):
            return ast.literal_eval(node.value)
    return None


def declares_info(directory) -> bool:
    module_file = directory / "module.py"
    return module_file.is_file() and literal_info(module_file) is not None


# A RedELK module is a directory whose module.py declares `info`. The rest are shared packages
# (c2api and its deliberate placeholder module.py, which exists only so that daemon.py skips the
# directory at debug level instead of logging an import error every minute).
SHIPPED_MODULES = [path for path in SHIPPED_DIRECTORIES if declares_info(path)]
SHIPPED_HELPERS = [path for path in SHIPPED_DIRECTORIES if not declares_info(path)]

VALID_TYPES = {"redelk_alarm", "redelk_enrich", "redelk_connector"}


def test_the_module_directory_is_not_empty():
    assert SHIPPED_MODULES, "no modules found; the discovery path is probably wrong"


@pytest.mark.parametrize("directory", SHIPPED_HELPERS, ids=lambda path: path.name)
def test_shared_helper_packages_are_importable(directory):
    """A directory under modules/ that is not a module is a shared package; it still has to be a
    real package or the modules importing it fail one by one."""
    assert (directory / "__init__.py").is_file(), f"{directory.name} is not a python package"


@pytest.mark.parametrize("directory", SHIPPED_HELPERS, ids=lambda path: path.name)
def test_a_shared_package_declares_neither_half_of_the_contract(directory):
    """daemon.py needs both `info` and `Module` before it runs anything, so a directory carrying
    exactly one of them is loaded, skipped and never heard from again - the failure mode that
    looks like an alarm which simply never fires."""
    module_file = directory / "module.py"
    if not module_file.is_file():
        return
    tree = ast.parse(module_file.read_text(encoding="utf-8"), filename=str(module_file))
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "Module" not in classes, (
        f"{directory.name} defines a Module class but no `info` dict; daemon.py will skip it"
    )


@pytest.mark.parametrize("directory", SHIPPED_MODULES, ids=lambda path: path.name)
def test_every_shipped_module_satisfies_the_contract(directory):
    """A module without `info` or `Module` is silently skipped at run time, which looks exactly
    like an alarm that never fires."""
    module_file = directory / "module.py"
    source = module_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_file))

    info = literal_info(module_file)
    assert info.get("type") in VALID_TYPES, f"{directory.name} declares type {info.get('type')!r}"
    for key in ("version", "name", "description", "submodule"):
        assert key in info, f"{directory.name}'s info has no {key!r}"

    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "Module" in classes, f"{directory.name} defines no Module class"

    module_class = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Module"
    )
    methods = {
        node.name
        for node in module_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    expected = "send_alarm" if info["type"] == "redelk_connector" else "run"
    assert expected in methods, f"{directory.name} has no {expected}() method"


@pytest.mark.parametrize("directory", SHIPPED_DIRECTORIES, ids=lambda path: path.name)
def test_every_shipped_module_parses(directory):
    """Byte-compilation of the whole tree, one directory at a time so the failure names the file."""
    for path in sorted(directory.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_shipped_submodule_names_are_unique():
    """The submodule name is the tag written onto every document; a duplicate merges two
    modules' results in Kibana."""
    seen = {}
    for directory in SHIPPED_MODULES:
        info = literal_info(directory / "module.py")
        submodule = info.get("submodule")
        assert submodule not in seen, (
            f"{directory.name} reuses the submodule name of {seen.get(submodule)}"
        )
        seen[submodule] = directory.name
