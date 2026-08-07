"""Allow `python -m redelk_setup` as an alternative to ./redelkctl."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
