
# import pdb
# pdb.set_trace()

class System():
    def __init__(self, components=None, threats=None):
        if (components == None):
            self.components = []
        else:
            self.components = componenets
        
        if (threats == None):
            self.threats = []
        else:
            self.threats = threats
        
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
            if (i.name == name):
                return i
                
    def add_component(self, component_type, name, level=0, users=None):
        if (component_type=="Computer"):
            self.components.append(Computer(name, level, users))
    
    def add_threats_from_csv(self, path):
        pass
        
    def add_threat_from_dict(self, threat):
        t = Threat(threat['eventid'], threat['risk'])
        if (threat['score_range'] != None):
            t.set_score_range(*threat['score_range']) 
        if (threat['labels'] != None):
            t.set_labels(threat['labels'])
        if (threat['user_level'] != None):
            t.set_user_level(threat['user_level'])
        if (threat['host_level'] != None):
            t.set_host_level(threat['host_level'])
        if (threat['description'] != None):
            t.set_description(threat['description'])
        self.threats.append(t)
    
    def get_risk_score(self, event):
        risk_score = 0.0
        for threat in self.threats:
            risk_score = risk_score + threat.how_bad(self, event)
        return risk_score

class Component():
    pass
    
class Computer(Component):
    def __init__(self, name, level, users=None):
        self.name = name
        self.level = level
        if (users == None):
            self.users = []
        else:
            self.users = users
        
    def add_user(self, name, level):
        self.users.append(User(name, level))

    def get_user_level(self, username):
        for user in self.users:
            if  (user.name == username):
                return user.level
    
class User():
    def __init__(self, name, level):
        self.name = name
        self.level = level

class Threat():
    def __init__(self, eventid, risk):
        self.eventid = eventid #what
        self.score_range = None #how bad it should be to be important
        self.labels = None #details
        self.user_level = None #who
        self.host_level = None #where
        self.risk = risk #damage
        self.description = 'Just because' #why it's dangerous
    
    def set_score_range(self, l_bound, u_bound):
        self.score_range = (l_bound, u_bound)
    
    def set_labels(self, labels):
        self.labels = set([])
        for label in labels:
            self.labels.add(label)
    
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
        if (self.eventid == event.eventid):
            danger = 0.0
            if (self.score_range == None):
                danger = danger + 1
            else:
                danger = danger + \
                    int(self.score_range[0] <=\
                        event.Score <=\
                        self.score_range[1])

            comp = system.get_component(event.Host)
            hostlevel == comp.level
            userlevel = comp.get_user_level(event.User)
            
            if (self.user_level == None):
                danger = danger + 1
            else:
                danger = danger + \
                    int(self.user_level.__contains__(userlevel))
            
            if (self.host_level == None):
                danger = danger + 1
            else:
                danger = danger + \
                    int(self.host_level.__contains__(hostlevel))
            
            danger = danger + \
                int(self.labels.__contains__(event.Name))
            
            danger = danger/4.0
            
            return self.risk*danger
        
if (__name__ == "__main__"):
    sys = System()
    sys.add_component("Computer", "DESKTOP-1", 0, [User('vasya', 0),\
                                                   User('masha', 1)])    
    sys.add_component("Computer", "DESKTOP-2", 0, [User('petya', 0),\
                                                   User('masha', 1)])    
    sys.add_component("Computer", "DESKTOP-3", 0, [User('katya', 0),\
                                                   User('masha', 1)])    
    sys.add_component("Computer", "DESKTOP-ADMIN", 1, [User('director', 0),\
                                                   User('masha', 1)])        
    sys.add_threat_from_dict({'eventid':1, \
                              'score_range':None,\
                              'labels':['powershell.exe'],\
                              'user_level':[0],\
                              'host_level': None,\
                              'risk': 100,\
                              'description': 'Обычный пользователь запустил powershel.exe'})
    sys.show_system()
    