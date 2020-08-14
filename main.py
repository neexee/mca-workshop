#!/usr/bin/env python3
import argparse
import os
from glob import glob

from modules.enrichment import enrich_events
from modules.known_threats import get_known_threats
from modules.sysmon import parse_files
from modules.threat_model import System, User


def main():
    args = _parse_args()
    files = _unfold_paths(args.paths)
    events = parse_files(files)
    print(f'Discovered {len(events)} events with id 1 and id 3 across {len(files)} file(s)')

    model = _create_model()
    enrich_events(events, showlog=True)
    for event in events:
        event.Risk = model.get_risk_score(event)
        print(event.EventId, 
              event.ProcessName, 
              event.User, 
              event.Host,
              event.Risk)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Analyze sysmon json-formated logs')
    parser.add_argument(
        "paths",
        help='Paths to separate json logs or directory containing them',
        nargs='+')
    return parser.parse_args()


def _unfold_paths(paths):
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(glob(os.path.join(path, '*.json')))
            continue
        files.append(path)
    return files


def _create_model():
    sys = System()
    sys.add_component("Computer", "Qishna", 0, [User('QISHNA\garip', 0)])
    for threat in get_known_threats():
        sys.add_threat_from_dict(threat)

    sys.show_system()
    return sys


if __name__ == '__main__':
    main()
