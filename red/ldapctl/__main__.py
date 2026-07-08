"""Enable `python -m ldapctl`. The installed console script `ldapctl` uses cli:main directly."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
