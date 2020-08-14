import datetime
import json
import os

from pathlib import Path
from typing import List, Tuple, Iterable
from datatypes.datatypes import Event

def parse_files(files: Iterable[Path]) -> Tuple[List[ProcessCreation], List[NetworkConnection]]:
    """
    Extract process creation and network connection events from json-formatted sysmon logs
    """
    count = 0
    N = 1
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
                    #import pdb
                    #pdb.set_trace()

                    proc = ProcessCreation(
                        Time=utctime,
                        Hashes=log_json['EventData']['Hashes'],
                        GUID=log_json['System']['Provider']['@Guid'],
                        Name=os.path.basename(log_json['EventData']['Image']),
                        User=log_json['EventData']['User'],
                        Host=log_json['System']['Computer'])
                    # print(log_json['EventData']['User'])
                    process_creations.append(proc)

                if event_id == 3:
                    # print(log_json['EventData'])
                    connection = NetworkConnection(
                        Time=utctime,
                        IP=log_json['EventData']['DestinationIp'],
                        Domain=log_json['EventData']['DestinationHostname'],
                        Protocol=log_json['EventData']['Protocol'])
                    network_connections.append(connection)
                    # print(log_json['EventData']['User'])
                    count = count + 1
                    # if (count >= N):
                        # break

    return process_creations, network_connections