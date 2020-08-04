

class Warnings(object):
    def __init__(self, list_of_events=None):
        if (list_of_events == None)
            self.list_of_events = set([])
        else:
            self.list_of_events = list_of_events
        
    def add_event(self, id, rate, description):
        self.list_of_events.add({"id": id,
                                 "user_level": ulevel,
                                 "comp_level":
                                 "rate": rate, 
                                 "decription":description})

