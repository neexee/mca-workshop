class System:
    def __init__(self, components=None, threats=None):
        self.components = [] if components is None else components
        self.threats = [] if threats is None else threats

    def show_system(self):
        print("Components:")
        print("===========")
        for comp in self.components:
            print("{}, level = {}".format(comp.name, comp.level))
            print("\t Users:")
            for user in comp.users:
                print("\t\t Name = {}, level = {}".format(user.name, user.level))
        print("Monitored threats:")
        print("==================")
        for th in self.threats:
            print("\t {0} {1}".format(th.risk, th.description))

    def get_component(self, name):
        for i in self.components:
            if i.name == name:
                return i

    def add_component(self, component_type, name, level=0, users=None):
        if component_type == "Computer":
            self.components.append(Computer(name, level, users))

    def add_threats_from_csv(self, path):
        pass

    def add_threat_from_dict(self, threat):
        t = Threat(threat['eventid'], threat['risk'])
        if threat['score_range'] is not None:
            t.set_score_range(*threat['score_range'])
        if threat['cmd_labels'] is not None:
            t.set_cmd_labels(threat['cmd_labels'])
        if threat['user_level'] is not None:
            t.set_user_level(threat['user_level'])
        if threat['host_level'] is not None:
            t.set_host_level(threat['host_level'])
        if threat['description'] is not None:
            t.set_description(threat['description'])
        self.threats.append(t)

    def get_risk_score(self, event):
        risk_score = 0.0
        t_list = []
        for threat in self.threats:
            impact = threat.how_bad(self, event)
            if impact > 0:
                risk_score += impact
                t_list.append(threat.description)
        return risk_score, t_list


class Component:
    pass


class Computer(Component):
    def __init__(self, name, level, users=None):
        self.name = name
        self.level = level
        self.users = [] if users is None else users

    def add_user(self, name, level):
        self.users.append(User(name, level))

    def get_user_level(self, username):
        for user in self.users:
            if user.name == username:
                return user.level
        return 1


class User:
    def __init__(self, name, level):
        self.name = name
        self.level = level


class Threat():
    def __init__(self, eventid, risk):
        self.eventid = eventid  # what
        self.score_range = None  # how bad it should be to be important
        self.cmd_labels = None  # details
        self.user_level = None  # who
        self.host_level = None  # where
        self.risk = risk  # damage
        self.description = 'Just because'  # why it's dangerous

    def set_score_range(self, l_bound, u_bound):
        self.score_range = (l_bound, u_bound)

    def set_cmd_labels(self, labels):
        self.cmd_labels = set([])
        for label in labels:
            self.cmd_labels.add(label)

    def set_user_level(self, levels):
        self.user_level = set([])
        for level in levels:
            self.user_level.add(level)

    def set_host_level(self, levels):
        self.host_level = set([])
        for level in levels:
            self.host_level.add(level)

    def set_description(self, string):
        self.description = str(string)

    def how_bad(self, system, event):
        danger = 0.0
        score = event.Score
        if (self.score_range is not None) and (self.score_range[0] <= score <= self.score_range[1]):
            danger += 0.4

        host_level = system.get_component(event.Host).level
        user_level = system.get_component(event.Host).get_user_level(event.User)
        if self.user_level is not None and user_level in self.user_level:
            danger += 0.2
        if self.host_level is not None and host_level in self.host_level:
            danger += 0.2

        if event.EventId == 1:
            cmd_line = event.Details['CmdLine']
            process_name = event.ProcessName
            if process_name in ['powershell.exe', 'cmd.exe']:
                for l in self.cmd_labels:
                    if cmd_line.find(l) > -1:
                        danger += 1.0 / len(self.cmd_labels)
        elif event.EventId == 3:
            process_name = event.ProcessName
            if process_name in self.cmd_labels:
                danger += 1.0
        else:
            danger += 1.0

        return self.risk * danger


if __name__ == "__main__":
    sys = System()
    sys.add_component("Computer", "Qishna", 0, [User('QISHNA\garip', 0)])
    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': (5, 100),
                              'cmd_labels': [],
                              'user_level': None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Malware detected!'})

    sys.add_threat_from_dict({'eventid': 3,
                              'score_range': (2, 100),
                              'cmd_labels': [],
                              'user_level': None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Bad connection detected!'})

    sys.add_threat_from_dict({'eventid': 1,
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
                              'description': 'Process Injection: Thread Execution Hijacking(T1055.003)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['at.exe', 'schtasks', 'taskeng.exe '],
                              'user_level': None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Scheduled Task/Job(T1053)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['.dll'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'Hijack Execution Flow(T1574)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['powershell.exe -ExecutionPolicy Bypass -C'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 100,
                              'description': 'User Execution(T1204)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['vssadmin.exe delete shadows /all /quiet',
                                             'wbadmin.exe delete catalog -quiet',
                                             'bcdedit.exe /set {{default}} bootstatuspolicy ignoreallfailures & bcdedit /set {{default}} recoveryenabled no'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 200,
                              'description': 'Inhibit System Recovery(T1490)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['sc query', 'net start >> %temp%\download',
                                             'net start >> %TEMP%\info.dat ',
                                             'tasklist', 'tasklist /svc',
                                             'net start'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'System Service Discovery(T1007)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['netstat -ano >> %temp%\download', 'net use',
                                             'net session', 'netstat -anpo tcp',
                                             'whoami', 'netstat -r', 'netstat -am', 'netstat -ano'
                                                                                    'netstat',
                                             'netsh wlan show networks mode=bssid', 'netsh wlan show interfaces'
                                                                                    'ipconfig', 'GetExtendedUdpTable',
                                             'arp -a', 'nbtstat'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'System Network Connections Discovery(T1049)'})

    sys.add_threat_from_dict({'eventid': 1,
                              'score_range': None,
                              'cmd_labels': ['net use \system\share /delete', 'net use * /DELETE /Y'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'Indicator Removal on Host(T1070)'})

    sys.add_threat_from_dict({'eventid': 3,
                              'score_range': None,
                              'cmd_labels': ['powershell.exe'],
                              'user_level': None,
                              'host_level': None,
                              'risk': 50,
                              'description': 'Strange connection'})

    sys.show_system()
