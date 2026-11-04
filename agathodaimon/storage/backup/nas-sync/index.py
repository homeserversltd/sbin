from importlib import import_module

main = import_module("agathodaimon.storage.backup.nas-sync._sync").main

if __name__ == "__main__":
    raise SystemExit(main())
