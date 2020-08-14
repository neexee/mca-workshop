#!/usr/bin/env python3
import argparse
import os
from glob import glob

from modules.threat_model import System, User
from modules.enrichment import enrich_events
from modules.sysmon import parse_files


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
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':(2, 100),
                              'cmd_labels':[],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Malware detected!'})
    
    sys.add_threat_from_dict({'eventid':3, 
                              'score_range':(2, 100),
                              'cmd_labels':[],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Bad connection detected!'})
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['CreateRemoteThread',
                                            'SuspendThread',
                                            'SetThreadContext',
                                            'ResumeThread', 
                                            'VirtualAllocEx',
                                            'WriteProcessMemory'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Process Injection: Thread Execution Hijacking(T1055.003)'})

    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['at.exe','schtasks','taskeng.exe '],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Scheduled Task/Job(T1053)'})
    
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['.dll','.DLL'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Hijack Execution Flow(T1574)'})
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['powershell.exe -ExecutionPolicy Bypass -C'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'User Execution(T1204)'})
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['vssadmin.exe delete shadows /all /quiet',
                                            'wbadmin.exe delete catalog -quiet',
                                            'bcdedit.exe /set {{default}} bootstatuspolicy ignoreallfailures & bcdedit /set {{default}} recoveryenabled no'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 200,
                              'description': 'Inhibit System Recovery(T1490)'})
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['sc query', 'net start >> %temp%\download', 'net start >> %TEMP%\info.dat ',
                                            'tasklist', 'tasklist /svc', 
                                            'net start'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'System Service Discovery(T1007)'})
    
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['netstat -ano >> %temp%\download','net use',
                                            'net session', 'netstat -anpo tcp',
                                            'whoami', 'netstat -r', 'netstat -am', 'netstat -ano'
                                            'netstat', 'netsh wlan show networks mode=bssid', 'netsh wlan show interfaces'
                                            'ipconfig','GetExtendedUdpTable','arp -a','nbtstat'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'System Network Connections Discovery(T1049)'})
                              
    sys.add_threat_from_dict({'eventid':1, 
                              'score_range':None,
                              'cmd_labels':['net use \system\share /delete', 'net use * /DELETE /Y'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'Indicator Removal on Host(T1070)'})
    
    sys.add_threat_from_dict({'eventid':3, 
                              'score_range':None,
                              'cmd_labels':['powershell.exe'],
                              'user_level':None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'Strange connection'})

    sys.show_system()
    
    return sys


if __name__ == '__main__':
    main()
