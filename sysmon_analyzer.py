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


class NetworkConnection:
    Time: datetime.datetime
    IP: str
    Domain: str


def scan(args):
    for files in args.file:
        with open(files, "r") as logs_in:
            filename = os.path.splitext(files)
            with open(filename[0] + '_ip_and_domains.json', "w") as logs_out_3:
                with open(filename[0] + '_hashes.json', "w") as logs_out_1:
                    for num, line in enumerate(logs_in, start=1):
                        log_json = json.loads(line)
                        
                        EventID = log_json['System']['EventID']['$']
                        UtcTime = log_json['EventData']['UtcTime']
                        
                        if EventID == 1:
                            proc = ProcessCreation()
                            proc.Time = UtcTime
                            proc.Hashes = log_json['EventData']['Hashes']
                            proc.GUID = log_json['System']['Provider']['@Guid']
                            net_dict = {'Record': num,"Date": proc.Time, "Hash": proc.Hashes, "GUID": proc.GUID}
                            logs_out_1.write(json.dumps(net_dict) + '\n')

                        if EventID == 3:
                            connection = NetworkConnection()
                            connection.Time = UtcTime
                            connection.IP = log_json['EventData']['DestinationIp']
                            connection.domain = log_json['EventData']['DestinationHostname']
                            net_dict = {'Record': num,"Date": connection.Time, "IP": connection.IP, "Domain": connection.domain}
                            logs_out_3.write(json.dumps(net_dict) + '\n')


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