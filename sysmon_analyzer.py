#!/usr/bin/env python3

import os
import json
import sys 
import argparse
import textwrap
import datetime
from glob import glob


class ProcessCreation:
    Time: datetime.datetime
    Hashes: str
    GUID: str
    Name: str
    User: str
    Host: str


class NetworkConnection:
    Time: datetime.datetime
    IP: str
    Domain: str
    Protocol: str


def scan(args):
    processList = []
    connectionList = []
    for files in args.file:
        with open(files, "r") as logs_in:
            for line in logs_in:
                log_json = json.loads(line)
                EventID = log_json['System']['EventID']['$']
                UtcTime = log_json['EventData']['UtcTime']
                        
                if EventID == 1:
                    proc = ProcessCreation()
                    proc.Time = UtcTime
                    proc.Hashes = log_json['EventData']['Hashes']
                    proc.GUID = log_json['System']['Provider']['@Guid']
                    proc.Name = log_json['EventData']['OriginalFileName']
                    proc.User = log_json['EventData']['User']
                    proc.Host = log_json['System']['Computer']
                    processList.append(proc)

                if EventID == 3:
                    connection = NetworkConnection()
                    connection.Time = UtcTime
                    connection.IP = log_json['EventData']['DestinationIp']
                    connection.domain = log_json['EventData']['DestinationHostname']
                    connection.Protocol = log_json['EventData']['Protocol']
                    connectionList.append(connection)

    return processList, connectionList


def scan_folder(args):
    files = glob(os.path.join(args.folder[0], "*.json"))
    args.__setattr__('file', files)
    scan(args)


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