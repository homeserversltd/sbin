"""Legacy vault-open adapter retained for existing callers."""
from agathodaimon.storage.vault.open._core import main

if __name__ == "__main__":
    raise SystemExit(main())
