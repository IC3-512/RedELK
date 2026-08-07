"""
Part of RedELK

The end-to-end tier. It is a package (rather than a bare directory of test files) so that the
helper modules next to the tests - fake_mythic.py and the fixtures/ payloads - have one
unambiguous import name, and so that a module called e.g. `conftest` or `fake_mythic` here can
never collide with a same-named module in the fast unit tier.

Nothing is imported here on purpose: importing the fixtures at package level would run the
docker probes during plain collection of the unit tier.

Authors:
- RedELK contributors
"""
