
class Firewall(object):
    def __init__(self, white_list=list()):
        self.white_list = whilte_list
    
    def add_app(self, ip):
        self.white_list.append(ip)
    