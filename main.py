#!/usr/bin/env python3
import os
import click
from extraction import extract_sysdiagnose
from parser import parse_all_logs
from database import load_apple_cell_db, match_cells
from reporter import generate_report

@click.command()
@click.argument('archive', type=click.Path(exists=True))
@click.option('-o', '--output', default='report.md', help='Output Markdown report path')
@click.option('--celldb', default=os.path.join('data','apple_cell_db.json'), type=click.Path(exists=True), help='Apple Cell DB JSON')
def main(archive, output, celldb):
    click.echo(f"Extracting: {archive}")
    workdir = extract_sysdiagnose(archive)
    click.echo("Parsing logs…")
    events, stages, packets, tlvs, toggles = parse_all_logs(workdir)
    click.echo(f"Events: {len(events)}, Stages: {len(stages)}, Packets: {len(packets)}, TLVs: {len(tlvs)}, Toggles: {len(toggles)}")
    click.echo(f"Loading DB: {celldb}")
    anomalies = match_cells(events, load_apple_cell_db(celldb))
    click.echo(f"Anomalies: {len(anomalies)}")
    click.echo(f"Generating report: {output}")
    generate_report(output, events, stages, packets, tlvs, toggles, anomalies)
    click.echo(f"Done. Report: {output}")

if __name__ == '__main__':
    main()
