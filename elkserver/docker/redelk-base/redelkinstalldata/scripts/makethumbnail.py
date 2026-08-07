#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Script to generate thumbnails of the screenshots pulled off the C2 servers.
The output is saved next to the input file as "<name>.thumb.jpg", which is the path
logstash writes into screenshot.thumb.

Called from cron as: makethumbnail.py /var/www/html/c2logs/

Three things were wrong with the v2 version, and together they meant that one bad file stopped
every thumbnail from that moment on:

  * the whole walk lived inside a single try/except, so the first unreadable image aborted the
    run - and because the loop starts over from the top on the next cron tick, it aborted every
    following run at the same file;
  * the handler itself raised: `logging.log("Error ", str(error))` passes a string where a log
    level is expected, so the only thing that ever reached the log was a TypeError;
  * `Image.ANTIALIAS` was removed in Pillow 10, so on the v3 base image every single resize
    raised AttributeError.

Authors:
- Outflank B.V. / Marc Smeets
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from PIL import Image

LOG_PATH = Path("/var/log/redelk/makethumbnail.log")

THUMB_SUFFIX = ".thumb.jpg"
THUMB_HEIGHT = 300

# Cobalt Strike writes .jpg; the other C2 frameworks store screenshots as .png. The thumbnail is
# always a .jpg, so the suffix check below is what keeps us from thumbnailing our own output.
SOURCE_EXTENSIONS = (".jpg", ".jpeg", ".png")

logger = logging.getLogger("makethumbnail")


def setup_logging() -> None:
    """Log to a rotating file when we may write one, and always to stderr for cron."""
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s -- %(message)s")
    logger.setLevel(logging.INFO)

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=2
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except OSError as error:
        logger.warning("could not open %s for writing: %s", LOG_PATH, error)


def make_thumbnail(source: Path, height: int = THUMB_HEIGHT) -> bool:
    """Write <source><THUMB_SUFFIX>. Returns True when a thumbnail was created.

    Never raises: a screenshot that arrived truncated over rsync, or a file that only looks like
    an image, must not stop the rest of the run.
    """
    target = source.with_name(source.name + THUMB_SUFFIX)
    if target.exists():
        return False

    # Written next to the target and moved into place, so nginx never serves a half-written
    # thumbnail and a crash does not leave one behind that we would skip forever after.
    temporary = source.with_name(f".{source.name}{THUMB_SUFFIX}.tmp")

    try:
        with Image.open(source) as image:
            if image.height <= 0 or image.width <= 0:
                logger.warning("skipping %s: image has no size", source)
                return False

            ratio = height / float(image.height)
            width = max(1, int(image.width * ratio))
            resized = image.resize((width, height), Image.Resampling.LANCZOS)
            # JPEG has no alpha channel; a PNG screenshot with transparency fails to save as RGBA.
            if resized.mode not in ("RGB", "L"):
                resized = resized.convert("RGB")
            resized.save(temporary, format="JPEG", quality=85)

        os.replace(temporary, target)
        logger.debug("created %s", target)
        return True
    except Exception as error:  # pylint: disable=broad-except
        # Pillow raises anything from UnidentifiedImageError to OSError to DecompressionBombError
        # here, and none of them is worth losing the rest of the directory over.
        logger.warning("could not create a thumbnail for %s: %s", source, error)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def walk(root: Path) -> tuple[int, int]:
    """Create the missing thumbnails under `root`. Returns (created, failed)."""
    created = 0
    failed = 0

    for directory, _, files in os.walk(root):
        for name in files:
            lowered = name.lower()
            if lowered.endswith(THUMB_SUFFIX) or not lowered.endswith(SOURCE_EXTENSIONS):
                continue

            source = Path(directory) / name
            if not source.is_file():
                continue

            if make_thumbnail(source):
                created += 1
            elif not source.with_name(name + THUMB_SUFFIX).exists():
                failed += 1

    return created, failed


def main(argv: list[str]) -> int:
    setup_logging()

    if len(argv) != 2:
        logger.error("usage: %s <directory>", Path(argv[0]).name)
        return 2

    root = Path(argv[1])
    if not root.is_dir():
        # Not an error worth mailing about every minute: the directory only exists once the first
        # C2 server has been synced.
        logger.info("%s does not exist (yet), nothing to do", root)
        return 0

    created, failed = walk(root)
    if created or failed:
        logger.info("created %d thumbnail(s), %d file(s) could not be read", created, failed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
