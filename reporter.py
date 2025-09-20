#!/usr/bin/env python3
from typing import List, Dict, Any

def generate_report(
    path: str,
    events: List[Dict[str, Any]],
    stages: List[Dict[str, Any]],
    packets: List[Dict[str, Any]],
    tlvs: List[Dict[str, Any]],
    toggles: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]]
) -> None:
    with open(path, 'w') as rpt:
        rpt.write('# Sysdiagnose Forensic Report\n\n')
        rpt.write('## Settings Toggles\n')
        if toggles:
            rpt.write('|Timestamp|Key|Value|\n|---|---|---|\n')
            for t in toggles:
                rpt.write(f"|{t['timestamp']}|{t['key']}|{t['value']}|\n")
        else:
            rpt.write('_None_\n')
        rpt.write('\n## Network Events\n')
        if events:
            rpt.write('|Timestamp|Process|Subsystem|Message|\n|---|---|---|---|\n')
            for e in events:
                msg = e['message'].replace('|','\\|')
                rpt.write(f"|{e['timestamp']}|{e['process']}|{e['subsystem']}|{msg}|\n")
        else:
            rpt.write('_None_\n')
        rpt.write('\n## Cell-ID Anomalies\n')
        if anomalies:
            rpt.write('|Timestamp|Cell ID|Message|\n|---|---|---|\n')
            for a in anomalies:
                msg = a['message'].replace('|','\\|')
                rpt.write(f"|{a['timestamp']}|{a['cell_id']}|{msg}|\n")
        else:
            rpt.write('_None_\n')
        rpt.write('\n## Verification Stages\n')
        if stages:
            rpt.write('|Stage|\n|---|\n')
            for s in stages:
                rpt.write(f"|{s['Stage']}|\n")
        else:
            rpt.write('_None_\n')
        rpt.write('\n## QMI Packets\n')
        if packets:
            keys = sorted({k for pkt in packets for k in pkt})
            rpt.write('|' + '|'.join(keys) + '|\n')
            rpt.write('|' + '---|'*len(keys) + '\n')
            for pkt in packets:
                rpt.write('|' + '|'.join(pkt.get(k,'') for k in keys) + '|\n')
        else:
            rpt.write('_None_\n')
        rpt.write('\n## QMI TLVs\n')
        if tlvs:
            rpt.write('|ID|Length|Data|\n|---|---|---|\n')
            for t in tlvs:
                rpt.write(f"|{t.get('ID','')}|{t.get('Length','')}|{t.get('Data','')}|\n")
        else:
            rpt.write('_None_\n')
    print(f"\nReport written to {path}")
