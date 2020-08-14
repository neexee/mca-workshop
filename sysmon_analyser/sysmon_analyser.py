import datetime
import json
import os

from pathlib import Path
from typing import List, Tuple, Iterable
from datatypes.datatypes import Event
import sysmon_analyser.riching_events as rich

def parse_files(files: Iterable[Path], showlog=False) -> List[Event]:
    """
    Extract process creation and network connection events from json-formatted sysmon logs
    """
    count = 0
    N = 1
    events = []  # type: List[Event]
    for files in files:
        with open(files, "r") as logs_in:
            for line in logs_in:
                log_json = json.loads(line)
                event_id = log_json['System']['EventID']['$']
                # print(event_id)
                utctime_str = log_json['EventData']['UtcTime']
                utctime = datetime.datetime.strptime(utctime_str, '%Y-%m-%d %H:%M:%S.%f')
                
                if event_id == 1:
                    # print(log_json['EventData']['CommandLine'])
                    pr_hash = log_json['EventData']['Hashes'].split(',')[1].split('=')[1]
                    new_event = Event(
                        Time=utctime,
                        EventId=1,
                        GUID=log_json['System']['Provider']['@Guid'],
                        ProcessName=os.path.basename(log_json['EventData']['Image']),
                        Image=log_json['EventData']['Image'],
                        User=log_json['EventData']['User'],
                        Host=log_json['System']['Computer'],
                        Details={'Hash': pr_hash, 'CmdLine': log_json['EventData']['CommandLine']},
                        Score=rich.get_file_hash_score(pr_hash),
                        Risk=())
                    events.append(new_event)
                    if showlog:
                        print(new_event.EventId, 
                              new_event.ProcessName, 
                              new_event.User, 
                              new_event.Host,
                              new_event.Details,
                              'hash_score = {}'.format(new_event.Score))

                if event_id == 3:
                                    
                    new_event = Event(
                        Time=utctime,
                        EventId=3,
                        GUID=log_json['System']['Provider']['@Guid'],
                        ProcessName=os.path.basename(log_json['EventData']['Image']),
                        Image=log_json['EventData']['Image'],
                        User=log_json['EventData']['User'],
                        Host=log_json['System']['Computer'],
                        Details={'IP_addres': log_json['EventData']['DestinationIp'],
                                 'Domain': log_json['EventData']['DestinationHostname']},
                        Score=rich.get_ip_score(log_json['EventData']['DestinationIp']),
                        Risk=())
                    events.append(new_event)
                    if showlog:
                        print(new_event.EventId, 
                              new_event.ProcessName, 
                              new_event.User, 
                              new_event.Host,
                              new_event.Details,
                              'ip_score = {}'.format(new_event.Score))
                    
    return events