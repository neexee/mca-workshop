import json
import requests
import os
from datetime import date
import math

sigma = 10
a = 3

# I consealed my WHOIS_KEY, I probably send you api key through telegram without posting it on github.
# You then can set enviroment variable WHOIS_KEY as I do in this code either through windows/linux or with
# means of pycharm enviroment variables mechanism

HOST_SITE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
API_key =  os.environ.get('WHOIS_KEY')

# The output of get_domain_score and get_ip_score functions is the probability of given domain being malicious
# It is a float number from 0 to 1

def get_domain_score(domain_name):
    return get(domain_name)
def get_ip_score(ip):
    return get(ip)

def normal_distribution(x):
    return (a * math.exp(-x / sigma) if a * math.exp(-x / sigma) < 1 else 1)

def print_pretty_json(data):
    print(json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False))

def get(domain_name):
        request = requests.get(f"{HOST_SITE}?apiKey={API_key}&domainName={domain_name}&outputFormat=JSON&ip=1")
        try:
            request.raise_for_status()
        except:
            raise Exception("An exception during connection to Whois server occured, check Whois service availibility.")
        data = request.json()
        #print_pretty_json(data)
        if ("ErrorMessage" in data):
            raise Exception(data['ErrorMessage']['msg'])
        q = data['WhoisRecord']['createdDate'].split('T')
        arr = list(map(int, q[0].split('-')))
        date_of_creation = date(arr[0], arr[1], arr[2])
        existence_time = date.today() - date_of_creation

        return (normal_distribution(existence_time.days))
