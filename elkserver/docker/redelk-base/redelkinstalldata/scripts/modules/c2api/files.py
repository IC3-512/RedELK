#!/usr/bin/env python3
"""
Part of RedELK

Where the API-based C2 connectors put the files and screenshots they pull out of a C2 database.

The layout matches what the file-based connectors produce with rsync, because the Kibana
dashboards and the nginx configuration only know about that one tree:

    /var/www/html/c2logs/<server>/<c2 program>/downloads/<file id>_<name>
    /var/www/html/c2logs/<server>/<c2 program>/screenshots/<file id>_<name>

nginx serves /var/www/html as the document root, so the URL of a stored file is its path with
/var/www/html removed - that is what goes into file.path_local and screenshot.full.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging
import os

from modules.c2api.util import safe_component

WWW_ROOT = "/var/www/html"
C2LOGS_ROOT = f"{WWW_ROOT}/c2logs"

# Screenshot thumbnails are what the Kibana screenshot dashboard renders in a table; the full
# images are megabytes each.
THUMBNAIL_HEIGHT = 300

logger = logging.getLogger("c2api.files")


class FileStore:
    """The download/screenshot directories of one C2 server."""

    def __init__(self, server: str, c2_program: str, root: str = C2LOGS_ROOT):
        self.server = safe_component(server, fallback="unknown-server")
        self.c2_program = safe_component(c2_program, fallback="unknown-c2")
        self.root = root
        self.base = os.path.join(root, self.server, self.c2_program)

    def path_for(self, kind: str, name: str) -> str:
        """Absolute path of a file. `kind` is 'downloads' or 'screenshots'."""
        return os.path.join(self.base, safe_component(kind, "downloads"), name)

    def url_for(self, path: str) -> str:
        """The URL nginx serves a stored file under."""
        if path.startswith(WWW_ROOT):
            return path[len(WWW_ROOT) :]
        return path

    def stored_name(self, file_id: str, file_name: str) -> str:
        """'<file id>_<name>', the same convention the Cobalt Strike downloads use.

        The id keeps two downloads of the same file name apart, and it is what makes the
        "do I already have this?" check exact rather than a guess based on the name.
        """
        return f"{safe_component(file_id, 'unknown')}_{safe_component(file_name, 'file')}"

    def exists(self, path: str) -> bool:
        """Do we already have this file? An empty file counts as missing, so it is retried."""
        try:
            return os.path.isfile(path) and os.path.getsize(path) > 0
        except OSError:
            return False

    def make_thumbnail(self, path: str) -> str | None:
        """Write '<path>.thumb.jpg' next to a screenshot. Returns its path, or None.

        Pillow is an optional dependency here on purpose: a missing or broken image library must
        cost the thumbnail, not the screenshot document.
        """
        thumb_path = f"{path}.thumb.jpg"
        if self.exists(thumb_path):
            return thumb_path
        try:
            from PIL import Image  # pylint: disable=import-outside-toplevel

            with Image.open(path) as image:
                image = image.convert("RGB")
                width = max(1, int(image.width * (THUMBNAIL_HEIGHT / float(image.height))))
                # Image.ANTIALIAS was removed in Pillow 10; LANCZOS is the same filter.
                image.resize((width, THUMBNAIL_HEIGHT), Image.LANCZOS).save(thumb_path, "JPEG")
            return thumb_path
        except Exception as error:  # pylint: disable=broad-except
            logger.warning("could not create a thumbnail for %s: %s", path, error)
            return None
