#!/usr/bin/env python3
"""
Part of RedELK

Not a RedELK module - a placeholder so the daemon does not report this shared package as broken.

daemon.py discovers modules by importing `modules.<directory>.module` for every directory under
scripts/modules/, and logs an error when that import fails. c2api is a library shared by the
API-based C2 connectors (enrich_mythic, enrich_outflankc2), not a module of its own, so without
this file every daemon run would log:

    could not import module c2api: No module named 'modules.c2api.module'

Because this file exports neither `info` nor `Module`, daemon.py recognises it as "not a RedELK
module" and skips it at debug level. Deleting it is fine the day daemon.py learns to ignore
directories that do not contain a module.py.

Authors:
- RedELK contributors
"""
