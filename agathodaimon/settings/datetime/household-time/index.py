"""Legacy argparse face for household-time primitives."""
from importlib import import_module

_household = import_module("agathodaimon.settings.datetime.household-time._household")
# Preserve the former module's public and private names for existing callers.
globals().update({name: value for name, value in vars(_household).items()
                  if not name.startswith("__")})

if __name__ == "__main__":
    raise SystemExit(_household.main())
