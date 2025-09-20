#!/usr/bin/env python3
import json, re
from typing import Dict, Any, List

def load_apple_cell_db(path: str) -> Dict[str, Any]:
    return json.load(open(path,'r'))

def match_cells(events: List[Dict[str, Any]], cell_db: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    pat = re.compile(r'Cell\s*ID[:=]\s*(\d+)', re.IGNORECASE)
    for ev in events:
        for m in pat.finditer(ev.get('message','')):
            cid = m.group(1)
            if cid not in cell_db:
                anomalies.append({'timestamp': ev.get('timestamp'), 'cell_id': cid, 'message': ev.get('message')})
    return anomalies
