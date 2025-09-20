import pytest
from parser import parse_all_logs

def test_parse_all_logs_empty(tmp_path):
    root = tmp_path / "dummy"
    root.mkdir()
    events, stages, packets, tlvs, toggles = parse_all_logs(str(root))
    assert isinstance(events, list)
    assert isinstance(stages, list)
    assert isinstance(packets, list)
    assert isinstance(tlvs, list)
    assert isinstance(toggles, list)
