

class Warnings(object):
    def __init__(self, list_of_events=[]):
        self.list_of_events = list_of_events
    def add_event(self, id, rate, description):
        self.list_of_events.add({"id": id,
                                 "user_level": ulevel,
                                 "comp_level":
                                 "Rate": rate, 
                                 "Decription":description})

