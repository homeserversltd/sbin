"""Root-owned Keyman vault policy writer for the mounted mapper."""
if __name__ == "__main__":
    from _policy import main
else:
    from agathodaimon.storage.vault.policy._policy import main

if __name__ == "__main__":
    raise SystemExit(main())
