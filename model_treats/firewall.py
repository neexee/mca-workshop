
class Firewall(object):
    def __init__(self, white_list=None):
        if (white_list == None):
            self.white_list = set([])
        else:
            self.white_list = white_list
        
    def add_app(self, ip):
        self.white_list.append(ip)
    