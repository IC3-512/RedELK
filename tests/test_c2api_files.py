"""
Part of RedELK

The FileStore thumbnailer.

A thumbnail is written into the tree nginx serves, so it must never be visible half-written. The
consequence is worse than a flicker: exists() treats any non-empty file as done, so a truncated
thumbnail is never regenerated and the screenshot dashboard keeps a broken image forever.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import os
import sys

import pytest

from conftest import DAEMON_SCRIPTS_DIR

pytest.importorskip("PIL", reason="Pillow is required to test the thumbnailer")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS_DIR))
    for name in [n for n in sys.modules if n.startswith("modules.c2api")]:
        del sys.modules[name]
    from modules.c2api.files import FileStore

    return FileStore("srv", "mythic", root=str(tmp_path))


def screenshot(store, name="shot.png", size=(40, 30)):
    from PIL import Image

    path = store.path_for("screenshots", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Image.new("RGB", size, "red").save(path, "PNG")
    return path


def test_a_thumbnail_is_created_and_readable_by_nginx(store):
    thumb = store.make_thumbnail(screenshot(store))

    assert thumb and os.path.isfile(thumb)
    # mkstemp-style 0600 is what made every download and screenshot 403.
    assert oct(os.stat(thumb).st_mode)[-3:] == "644"


def test_no_temporary_file_is_left_behind(store):
    path = screenshot(store)
    store.make_thumbnail(path)

    directory = os.path.dirname(path)
    assert [n for n in os.listdir(directory) if n.endswith(".tmp")] == []


def test_an_unreadable_screenshot_produces_no_thumbnail(store):
    path = store.path_for("screenshots", "truncated.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # A PNG header and nothing else - what a screenshot interrupted mid-transfer looks like.
    with open(path, "wb") as handle:
        handle.write(b"\x89PNG\r\n\x1a\n")

    assert store.make_thumbnail(path) is None

    directory = os.path.dirname(path)
    leftovers = [n for n in os.listdir(directory) if n != "truncated.png"]
    assert leftovers == [], f"a failed thumbnail left {leftovers} behind"


def test_the_thumbnail_is_never_written_to_the_path_nginx_serves(store, monkeypatch):
    """Atomicity, stated directly: the encoder must not write to the published path.

    This is the property, not the mechanism - Pillow writing progressively to thumb_path is exactly
    what let nginx serve a half-encoded JPEG.
    """
    from PIL import Image

    path = screenshot(store)
    thumb_path = f"{path}.thumb.jpg"
    written_to = []
    original_save = Image.Image.save

    def recording_save(self, fp, *args, **kwargs):
        written_to.append(str(fp))
        return original_save(self, fp, *args, **kwargs)

    monkeypatch.setattr(Image.Image, "save", recording_save)
    store.make_thumbnail(path)

    assert written_to, "nothing was encoded"
    assert thumb_path not in written_to, "the encoder wrote straight to the published path"


def test_a_crash_while_encoding_leaves_nothing_for_nginx_to_serve(store, monkeypatch):
    """The failure that makes it permanent: exists() treats any non-empty file as done."""
    from PIL import Image

    path = screenshot(store)
    thumb_path = f"{path}.thumb.jpg"

    def die_halfway(self, fp, *_args, **_kwargs):
        # A full disk or a killed process: some bytes land, then the write fails.
        with open(fp, "wb") as handle:
            handle.write(b"\xff\xd8\xff\xe0 partial jpeg")
        raise OSError("No space left on device")

    monkeypatch.setattr(Image.Image, "save", die_halfway)
    assert store.make_thumbnail(path) is None

    assert not os.path.exists(thumb_path), "a half-written thumbnail is now permanent"
    directory = os.path.dirname(path)
    assert [n for n in os.listdir(directory) if n.endswith(".tmp")] == []


def test_an_existing_thumbnail_is_not_regenerated(store):
    path = screenshot(store)
    first = store.make_thumbnail(path)
    stamp = os.stat(first).st_mtime_ns

    assert store.make_thumbnail(path) == first
    assert os.stat(first).st_mtime_ns == stamp
