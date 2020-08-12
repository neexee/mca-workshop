#!/usr/bin/env python3

import os
import json
import sys 
import argparse
import textwrap
import datetime
from dataclasses import dataclass
from glob import glob
from pathlib import Path
from typing import List, Tuple, Iterable


@dataclass
class ProcessCreation:
    Time: datetime.datetime
    Hashes: str
    GUID: str
    Name: str
    User: str
    Host: str


@dataclass
class NetworkConnection:
    Time: datetime.datetime
    IP: str
    Domain: str
    Protocol: str


def scan(files: Iterable[Path]) -> Tuple[List[ProcessCreation], List[NetworkConnection]]:
    process_creations = []  # type: List[ProcessCreation]
    network_connections = []  # type: List[NetworkConnection]
    for files in files:
        with open(files, "r") as logs_in:
            for line in logs_in:
                log_json = json.loads(line)
                event_id = log_json['System']['EventID']['$']
                utctime_str = log_json['EventData']['UtcTime']
                utctime = datetime.datetime.strptime(utctime_str, '%Y-%m-%d %H:%M:%S.%f')

                if event_id == 1:
                    proc = ProcessCreation(
                        Time=utctime,
                        Hashes=log_json['EventData']['Hashes'],
                        GUID=log_json['System']['Provider']['@Guid'],
                        Name=log_json['EventData']['OriginalFileName'],
                        User=log_json['EventData']['User'],
                        Host=log_json['System']['Computer'])
                    process_creations.append(proc)

                if event_id == 3:
                    connection = NetworkConnection(
                        Time=utctime,
                        IP=log_json['EventData']['DestinationIp'],
                        Domain=log_json['EventData']['DestinationHostname'],
                        Protocol=log_json['EventData']['Protocol'])
                    network_connections.append(connection)

    return process_creations, network_connections


def scan_folder(args):
    files = glob(os.path.join(args.folder[0], "*.json"))
    args.__setattr__('file', files)
    scan(args.files)


def parse_args():
    parser = argparse.ArgumentParser(description='Analyze sysmon json-formated logs', 
                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                    epilog=textwrap.dedent('''
                                    
                                                USAGE: 
                                                python sysmon_analyzer.py scan -f filename1.json filename2.json ...
                                                OR
                                                python sysmon_analyzer.py scan_folder -d Path_to_folder
                                                
                                                '''))

    subparser = parser.add_subparsers()

    fl_parser = subparser.add_parser('scan')
    fl_parser.add_argument('--file', '-f', nargs='+', action='store', help='Sets input json logs')
    fl_parser.set_defaults(func=scan)

    fd_parser = subparser.add_parser('scan_folder')
    fd_parser.add_argument('--folder', '-d', nargs='+', action='store', help='Sets input folder with json logs')
    fd_parser.set_defaults(func=scan_folder)
    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()
    try:
        args.func(args)
    except:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()