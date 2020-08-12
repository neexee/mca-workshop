import datetime
import json

from dataclasses import dataclass
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


def parse_files(files: Iterable[Path]) -> Tuple[List[ProcessCreation], List[NetworkConnection]]:
    """
    Extract process creation and network connection events from json-formatted sysmon logs
    """
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
