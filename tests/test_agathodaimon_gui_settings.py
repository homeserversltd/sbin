import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AgathodaimonGuiSettingsTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [str(ROOT / "agathodaimon/cli.py"), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_settings_help_resolves_renamed_path(self):
        process = self.run_cli("gui", "settings", "--help")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["path"], "gui/settings")

    def test_retired_noun_is_rejected(self):
        retired = "update" + "-" + "modal"
        process = self.run_cli("gui", retired, "--help")
        self.assertNotEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
