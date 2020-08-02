import os
import json
import sys 
import argparse
import textwrap
from glob import glob


def scan(args):
    for files in args.file:
        with open(files, "r") as logs_in:
            with open(files[:-5] + '_ip_and_domens.json', "w") as logs_out_3:
                with open(files[:-5] + '_hashes.json', "w") as logs_out_1:
                    for num, line in enumerate(logs_in, start=1):
                        log_json = json.loads(line)
                        
                        EventID = log_json['System']['EventID']['$']
                        UtcTime = ip = log_json['EventData']['UtcTime']
                        
                        if EventID == 1:
                            hashes = log_json['EventData']['Hashes']
                            net_dict = {'Record': num,"Date": UtcTime, "Hash": hashes}
                            logs_out_1.write(json.dumps(net_dict) + '\n')

                        if EventID == 3:
                            ip = log_json['EventData']['DestinationIp']
                            domain = log_json['EventData']['DestinationHostname']
                            net_dict = {'Record': num,"Date": UtcTime, "IP": ip, "Domain": domain}
                            logs_out_3.write(json.dumps(net_dict) + '\n')


def scan_folder(args):
    files = glob(os.path.join(args.folder[0], "*.json"))
    args.__setattr__('file', files)
    scan(args)


parser = argparse.ArgumentParser(description='This script analyze sysmon json-formated logs', 
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=textwrap.dedent('''
                                 
                                              INPUT FORMAT: 
                                              python sysmon_analyzer scan -f filename1.json filename2.json ...
                                              OR
                                              python sysmon_analyzer scan_folder -folder Path_to_folder
                                              OUTPUT FOLDER:
                                              \logs\output_filename1.json
                                              
                                              '''))

subparser = parser.add_subparsers()

fl_parser = subparser.add_parser('scan')
fl_parser.add_argument('--file', '-f', nargs='+', action='store', help='Sets input json logs')
fl_parser.set_defaults(func=scan)

fd_parser = subparser.add_parser('scan_folder')
fd_parser.add_argument('--folder', '-fd', nargs='+', action='store', help='Sets input folder with json logs')
fd_parser.set_defaults(func=scan_folder)


args = parser.parse_args()
try:
    args.func(args)
except Exception as error:
    parser.print_help()
    print("Error: %s\n" % error)