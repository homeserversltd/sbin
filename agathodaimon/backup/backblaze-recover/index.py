from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

_TARGET = Path(__file__).resolve().parents[1] / "backblaze-config" / "index.py"
_SPEC = importlib.util.spec_from_file_location("agathodaimon.backup.backblaze_config_face", _TARGET)
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MOD
assert _SPEC.loader is not None
_SPEC.loader.exec_module(_MOD)
globals().update({k:v for k,v in vars(_MOD).items() if not k.startswith("__")})
