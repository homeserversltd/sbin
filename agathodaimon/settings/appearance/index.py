import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon.settings._shared import *
from agathodaimon.settings._shared import family_main

def main(argv=None):
    return family_main("appearance", argv)
