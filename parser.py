#!/usr/bin/env python3
import os, re, json, plistlib
from typing import List, Dict, Any, Tuple

# Unified log event patterns
EVENT_PATTERNS = [
    re.compile(r"\bCell\s*ID[:=]\s*\d+\b", re.IGNORECASE),
    re.compile(r"\battach(?:ed)?\b", re.IGNORECASE),
    re.compile(r"\bdetach(?:ed)?\b", re.IGNORECASE),
    re.compile(r"\bAirplane Mode\b", re.IGNORECASE),
    re.compile(r"\bcall failed\b", re.IGNORECASE)
]
# QMI TLV patterns
TLV_START = re.compile(r'^TLV$', re.IGNORECASE)
ID_RE     = re.compile(r'^ID\s*0x([0-9A-Fa-f]+)')
LEN_RE    = re.compile(r'^Length\s*(\d+)')
DATA_RE   = re.compile(r'^Data\s*([0-9A-Fa-f ]+)')
# QMI packet header keyword
PACKET_HEADER = 'QMI Packet'


def find_json_paths(root_dir: str) -> List[str]:
    paths = []
    for dp,_,files in os.walk(root_dir):
        for f in files:
            if f.lower().endswith('.json'):
                paths.append(os.path.join(dp,f))
    return paths


def parse_unified_jsons(json_paths: List[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for p in json_paths:
        try:
            with open(p,'r',errors='ignore') as fp:
                for line in fp:
                    try:
                        entry = json.loads(line)
                    except:
                        continue
                    msg = entry.get('eventMessage') or entry.get('message','')
                    if any(rx.search(msg) for rx in EVENT_PATTERNS):
                        events.append({
                            'timestamp': entry.get('timestamp'),
                            'process': entry.get('processImagePath') or entry.get('process',''),
                            'subsystem': entry.get('subsystem',''),
                            'message': msg
                        })
        except:
            pass
    return events


def parse_plist_toggles(root_dir: str) -> List[Dict[str, Any]]:
    toggles: List[Dict[str, Any]] = []
    for dp,_,files in os.walk(root_dir):
        for f in files:
            if f == 'MCSettingsEvents.plist':
                try:
                    data = plistlib.load(open(os.path.join(dp,f),'rb'))
                    for ev in data.get('events',[]):
                        toggles.append({
                            'timestamp': ev.get('timestamp'),
                            'key': ev.get('key'),
                            'value': ev.get('value')
                        })
                except:
                    pass
    return toggles


def parse_qmi_tlvs(root_dir: str) -> List[Dict[str, Any]]:
    tlvs: List[Dict[str, Any]] = []
    for dp,_,files in os.walk(root_dir):
        for f in files:
            low = f.lower()
            if low.endswith('.dump') or 'qmi' in low:
                try:
                    lines = open(os.path.join(dp,f),'r',errors='ignore').splitlines()
                except:
                    continue
                i = 0
                while i < len(lines):
                    if TLV_START.match(lines[i].strip()):
                        entry: Dict[str, Any] = {}
                        for j in range(i+1, min(i+6,len(lines))):
                            ln = lines[j].strip()
                            if m := ID_RE.match(ln): entry['ID'] = m.group(1)
                            if m := LEN_RE.match(ln): entry['Length'] = m.group(1)
                            if m := DATA_RE.match(ln): entry['Data'] = m.group(1)
                        if entry:
                            tlvs.append(entry)
                    i += 1
    return tlvs


def parse_qmi_packets(root_dir: str) -> List[Dict[str, Any]]:
    packets: List[Dict[str, Any]] = []
    for dp,_,files in os.walk(root_dir):
        for f in files:
            low = f.lower()
            if low.endswith('.dump') or 'qmi' in low:
                try:
                    lines = open(os.path.join(dp,f),'r',errors='ignore').splitlines()
                except:
                    continue
                i = 0
                while i < len(lines):
                    if lines[i].strip() == PACKET_HEADER:
                        pkt: Dict[str, Any] = {}
                        i += 1
                        while i < len(lines) and lines[i].strip():
                            ln = lines[i].strip()
                            if ':' in ln:
                                k,v = ln.split(':',1)
                                pkt[k.strip()] = v.strip()
                            i += 1
                        packets.append(pkt)
                    i += 1
    return packets


def parse_verification_stages(root_dir: str) -> List[Dict[str, Any]]:
    stages: List[Dict[str, Any]] = []
    for dp,_,files in os.walk(root_dir):
        for f in files:
            if f.lower().endswith(('.log','.txt')):
                try:
                    for line in open(os.path.join(dp,f),'r',errors='ignore'):
                        if m := re.match(r'^STAGE: (.+)$', line.strip()):
                            stages.append({'Stage': m.group(1)})
                except:
                    pass
    return stages


def parse_all_logs(root_dir: str) -> Tuple[
    List[Dict[str,Any]],
    List[Dict[str,Any]],
    List[Dict[str,Any]],
    List[Dict[str,Any]],
    List[Dict[str,Any]]
]:
    return (
        parse_unified_jsons(find_json_paths(root_dir)),
        parse_verification_stages(root_dir),
        parse_qmi_packets(root_dir),
        parse_qmi_tlvs(root_dir),
        parse_plist_toggles(root_dir)
    )
