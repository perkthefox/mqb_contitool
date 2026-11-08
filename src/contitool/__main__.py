"""Allow `python -m contitool` execution."""

import sys

from contitool.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
