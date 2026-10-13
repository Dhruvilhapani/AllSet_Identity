"""db/005_seed_permissions.sql must match the seed JSON it is generated from.

The JSON is what the equivalence test checks, so a hand edit to the SQL, or a
JSON change without regenerating, would ship grants nobody tested.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_committed_seed_sql_matches_the_seed_json():
    spec = importlib.util.spec_from_file_location('build_seed_sql', ROOT / 'scripts' / 'build_seed_sql.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    committed = (ROOT / 'db' / '005_seed_permissions.sql').read_text(encoding='utf-8')
    assert committed == module.build(), 'run: python scripts/build_seed_sql.py'
