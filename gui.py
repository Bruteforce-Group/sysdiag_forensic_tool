#!/usr/bin/env python3
# gui.py
# PySimpleGUI front-end for sysdiag_forensic_tool

import os
import PySimpleGUI as sg
from extraction import extract_sysdiagnose
from parser import parse_all_logs
from database import load_apple_cell_db, match_cells
from reporter import generate_report

def main_gui():
    sg.theme('DarkBlue')
    layout = [
        [sg.Text('Sysdiagnose Forensic Tool', font=('Helvetica', 20))],
        [sg.Text('Sysdiagnose Archive:'), 
         sg.Input(key='archive'), sg.FileBrowse(file_types=(('GZIP','*.tar.gz'),))],
        [sg.Text('Apple Cell DB (.json):'), 
         sg.Input(default_text=os.path.join('data','apple_cell_db.json'), key='celldb'), 
         sg.FileBrowse(file_types=(('JSON','*.json'),))],
        [sg.Text('Output Report (.md):'), 
         sg.Input(default_text='report.md', key='output'), 
         sg.FileSaveAs(file_types=(('Markdown','*.md'),))],
        [sg.Button('Analyze'), sg.Button('Exit')],
        [sg.Multiline(size=(80,10), key='log', autoscroll=True, disabled=True)]
    ]
    window = sg.Window('Sysdiagnose Forensic Tool', layout, finalize=True)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Exit'):
            break
        if event == 'Analyze':
            archive = values['archive']
            celldb  = values['celldb']
            output  = values['output']
            log_elem = window['log']
            log_elem.update('▶ Extracting archive…\n')
            try:
                workdir = extract_sysdiagnose(archive)
                log_elem.update('▶ Parsing logs…\n')
                events, stages, packets, tlvs, toggles = parse_all_logs(workdir)
                log_elem.update(f'Parsed: {len(events)} events, {len(stages)} stages, {len(packets)} packets, {len(tlvs)} TLVs, {len(toggles)} toggles\n')
                log_elem.update('▶ Loading cell DB…\n')
                cell_db = load_apple_cell_db(celldb)
                anomalies = match_cells(events, cell_db)
                log_elem.update(f'Found {len(anomalies)} anomalous cell IDs\n')
                log_elem.update('▶ Generating report…\n')
                generate_report(output, events, stages, packets, tlvs, toggles, anomalies)
                log_elem.update(f'✅ Report saved to: {output}\n')
            except Exception as e:
                log_elem.update(f'❌ Error: {e}\n')
    window.close()

if __name__ == '__main__':
    main_gui()
