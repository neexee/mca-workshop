import firewall
import antimalware

# import pdb
# pdb.set_trace()

class System():
    current_id = 0
    def __init__(self, list_of_components=[], warnings=[]):
        self.loc = list_of_components
        self.warnings = warnings
        
    def print_components(self):
        for i in self.loc:
            print(i.id, ", ",type(i))
            
    def get_component(self, id):
        for i in self.loc:
            if (i.id == id):
                return i
                
    def add_component(self, component_type):
        if (component_type=="Computer"):
            self.loc.append(Computer(self.current_id))
            self.current_id = self.current_id + 1
            

class Component():
    pass
    
class Computer(Component):
    def __init__(self, id, firewall=None, antimalware=None, level=0, users=None):
        self.id = id
        self.firewall = firewall
        self.antimalware = antimalware
        self.level = level
        if (users == None):
            self.users = []
            
    def add_user(self, name, level):
        pass

class User():
    def __init__(self, name="admin", level=0):
        self.name = name
        self.level = level

system = System()
for i in range(3):
    system.add_component("Computer")
system.print_components()

