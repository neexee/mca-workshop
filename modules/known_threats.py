KNOWN_THREATS = [
    {
        'eventid': 1,
        'score_range': (2, 100),
        'cmd_labels': [],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'Malware detected!'
    },
    {
        'eventid': 3,
        'score_range': (2, 100),
        'cmd_labels': [],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'Suspicious connection detected!'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['CreateRemoteThread',
                       'SuspendThread',
                       'SetThreadContext',
                       'ResumeThread',
                       'VirtualAllocEx',
                       'WriteProcessMemory'],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'Process Injection: Thread Execution Hijacking(T1055.003)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['at.exe', 'schtasks', 'taskeng.exe '],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'Scheduled Task/Job(T1053)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['.dll', '.DLL'],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'Hijack Execution Flow(T1574)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['powershell.exe -ExecutionPolicy Bypass -C'],
        'user_level': None,
        'host_level': None,
        'risk': 100,
        'description': 'User Execution(T1204)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['vssadmin.exe delete shadows /all /quiet',
                       'wbadmin.exe delete catalog -quiet',
                       'bcdedit.exe /set {{default}} bootstatuspolicy ignoreallfailures & bcdedit /set {{default}} recoveryenabled no'],
        'user_level': None,
        'host_level': None,
        'risk': 200,
        'description': 'Inhibit System Recovery(T1490)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['sc query', 'net start >> %temp%\download', 'net start >> %TEMP%\info.dat ',
                       'tasklist', 'tasklist /svc',
                       'net start'],
        'user_level': None,
        'host_level': None,
        'risk': 50,
        'description': 'System Service Discovery(T1007)'
    },
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['netstat -ano >> %temp%\download', 'net use',
                       'net session', 'netstat -anpo tcp',
                       'whoami', 'netstat -r', 'netstat -am', 'netstat -ano'
                                                              'netstat', 'netsh wlan show networks mode=bssid',
                       'netsh wlan show interfaces'
                       'ipconfig', 'GetExtendedUdpTable', 'arp -a', 'nbtstat'],
        'user_level': None,
        'host_level': None,
        'risk': 50,
        'description': 'System Network Connections Discovery(T1049)'},
    {
        'eventid': 1,
        'score_range': None,
        'cmd_labels': ['net use \system\share /delete', 'net use * /DELETE /Y'],
        'user_level': None,
        'host_level': None,
        'risk': 50,
        'description': 'Indicator Removal on Host(T1070)'
    },
    {
        'eventid': 3,
        'score_range': None,
        'cmd_labels': ['powershell.exe'],
        'user_level': None,
        'host_level': None,
        'risk': 50,
        'description': 'Suspicious connection from powershell'
    }
]


def get_known_threats():
    return KNOWN_THREATS
