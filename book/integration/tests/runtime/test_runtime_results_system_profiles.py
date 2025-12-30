import json
from pathlib import Path

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))

def test_system_profiles_present_in_runtime_results():
    path = ROOT / 'book' / 'experiments' / 'runtime-checks' / 'out' / 'runtime_results.json'
    assert path.exists(), 'missing runtime_results.json'
    data = json.loads(path.read_text())
    for key in ['sys:airlock', 'sys:bsd']:
        assert key in data, f'missing runtime result for {key}'
        entry = data[key]
        probes = entry.get('probes') or []
        assert probes, f'expected probes for {key}'
        for probe in probes:
            assert 'exit_code' in probe
            assert 'expected' in probe
            assert 'actual' in probe
