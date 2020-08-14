import datetime
import json
import os

from dataclasses import dataclass
from pathlib import Path
from typing import List, Iterable


@dataclass
class Event:
    Time: datetime.datetime
    EventId: int
    GUID: str
    ProcessName: str
    Image: str
    User: str
    Host: str
    Details: dict
    Score: float  # enriched event
    Risk: tuple  # from model


def parse_files(files: Iterable[Path]) -> List[Event]:
    """
    Extract process creation and network connection events from json-formatted sysmon logs
    """
    events = []  # type: List[Event]
    for files in files:
        with open(files, "r") as logs_in:
            for line in logs_in:
                log_json = json.loads(line)
                event_id = log_json['System']['EventID']['$']
                utctime_str = log_json['EventData']['UtcTime']
                utctime = datetime.datetime.strptime(utctime_str, '%Y-%m-%d %H:%M:%S.%f')

                if event_id == 1:
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
                        Score=0,
                        Risk=())
                    events.append(new_event)

                if event_id == 3:
                    new_event = Event(
                        Time=utctime,
                        EventId=3,
                        GUID=log_json['System']['Provider']['@Guid'],
                        ProcessName=os.path.basename(log_json['EventData']['Image']),
                        Image=log_json['EventData']['Image'],
                        User=log_json['EventData']['User'],
                        Host=log_json['System']['Computer'],
                        Details={'IP_address': log_json['EventData']['DestinationIp'],
                                 'Domain': log_json['EventData']['DestinationHostname']},
                        Score=0,
                        Risk=())
                    events.append(new_event)

    return events
