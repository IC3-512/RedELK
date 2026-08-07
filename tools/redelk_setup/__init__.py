"""
Part of RedELK

redelkctl - the RedELK deployment tool.

One configuration file (redelk.yml) drives certificate generation, the docker environment, the
daemon configuration, the nginx basic-auth file, cron schedules and the installation packages for
redirectors and C2 servers.

Authors:
- RedELK contributors
"""

__all__ = ["__version__"]

__version__ = "3.0.0"
