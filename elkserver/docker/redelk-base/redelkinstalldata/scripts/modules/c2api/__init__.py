#!/usr/bin/env python3
"""
Part of RedELK

Shared building blocks for the C2 connectors that talk to a C2 framework's own API instead of
tailing log files (Mythic, Outflank C2).

Nothing is imported here on purpose. `cursor` needs modules.helpers, which needs a working
/etc/redelk/config.json and the Elasticsearch client, while `util` and `attack` are pure and are
imported by the modules' offline unit tests. Importing the submodules from this package would
drag Elasticsearch into every one of those tests.

Import what you need directly:

    from modules.c2api.http import ApiClient, GraphQLClient
    from modules.c2api.cursor import Cursor
    from modules.c2api.files import FileStore
    from modules.c2api import attack, util

Authors:
- RedELK contributors
"""
