"""
Part of RedELK

Tests for the screenshot thumbnailer.

The regression that matters here: v2 wrapped the whole directory walk in one try/except whose
handler itself raised (`logging.log("Error ", ...)`), so the first unreadable file stopped
thumbnail generation - not just for that run, but for every run after it, because the walk starts
at the top again every minute. A directory holding one good image and one corrupt file must
therefore produce exactly one thumbnail and exit cleanly.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    REPO_ROOT
    / "elkserver"
    / "docker"
    / "redelk-base"
    / "redelkinstalldata"
    / "scripts"
    / "makethumbnail.py"
)

Image = pytest.importorskip("PIL.Image", reason="Pillow is required to test the thumbnailer")


@pytest.fixture
def makethumbnail(tmp_path, monkeypatch):
    """Import makethumbnail.py by path, with its log file redirected into tmp_path."""
    spec = importlib.util.spec_from_file_location("redelk_makethumbnail", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "LOG_PATH", tmp_path / "logs" / "makethumbnail.log")
    yield module
    del sys.modules[spec.name]


def write_image(path: Path, size=(800, 600), mode="RGB") -> Path:
    """Write a real image file."""
    Image.new(mode, size, color="red").save(path)
    return path


def test_one_good_and_one_corrupt_file(makethumbnail, tmp_path):
    """One thumbnail is produced, the corrupt file is skipped, and nothing raises."""
    screenshots = tmp_path / "c2logs" / "cs1" / "screenshots"
    screenshots.mkdir(parents=True)

    write_image(screenshots / "screen_1_1518442534.jpg")
    # Not an image: what a truncated rsync of a screenshot looks like.
    (screenshots / "screen_2_1518442535.jpg").write_bytes(b"\xff\xd8\xff\xe0 this is not a JPEG")
    (screenshots / "notes.txt").write_text("not an image either", encoding="utf-8")

    exit_code = makethumbnail.main(["makethumbnail.py", str(tmp_path / "c2logs")])

    assert exit_code == 0

    thumbnails = sorted(path.name for path in screenshots.glob("*.thumb.jpg"))
    assert thumbnails == ["screen_1_1518442534.jpg.thumb.jpg"]

    # And it is a usable image of the expected height.
    with Image.open(screenshots / thumbnails[0]) as thumbnail:
        assert thumbnail.height == makethumbnail.THUMB_HEIGHT
        assert thumbnail.width == 400  # 800x600 scaled to a height of 300
        assert thumbnail.format == "JPEG"

    # No temporary files left behind by the failed conversion.
    assert not list(screenshots.glob(".*tmp"))


def test_existing_thumbnails_are_not_regenerated(makethumbnail, tmp_path):
    """A second run is a no-op, so cron running every minute does not rewrite every thumbnail."""
    screenshots = tmp_path / "shots"
    screenshots.mkdir()
    source = write_image(screenshots / "screen_3_1518442536.jpg")

    assert makethumbnail.main(["makethumbnail.py", str(screenshots)]) == 0
    thumbnail = source.with_name(source.name + ".thumb.jpg")
    first = thumbnail.stat().st_mtime_ns

    assert makethumbnail.make_thumbnail(source) is False
    assert thumbnail.stat().st_mtime_ns == first


def test_png_with_alpha_is_converted(makethumbnail, tmp_path):
    """RGBA cannot be saved as JPEG; screenshots from Sliver and Mythic are PNG."""
    screenshots = tmp_path / "shots"
    screenshots.mkdir()
    source = write_image(screenshots / "screenshot.png", size=(400, 200), mode="RGBA")

    assert makethumbnail.make_thumbnail(source) is True
    with Image.open(source.with_name(source.name + ".thumb.jpg")) as thumbnail:
        assert thumbnail.mode == "RGB"


def test_missing_directory_is_not_an_error(makethumbnail, tmp_path):
    """/var/www/html/c2logs only exists once a C2 server has been synced."""
    assert makethumbnail.main(["makethumbnail.py", str(tmp_path / "nope")]) == 0


def test_wrong_arguments(makethumbnail):
    """The cron entry passes exactly one argument; anything else is a usage error."""
    assert makethumbnail.main(["makethumbnail.py"]) == 2
