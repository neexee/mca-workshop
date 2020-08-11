import json
import requests
import os
from datetime import datetime, date

HOST_SITE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
API_key =  os.environ.get('WHOIS_KEY')

def print_pretty_json(data):
    print(json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False))

def get_domain_score(domain_name):
    return get(domain_name)
def get_ip_score(ip):
    return get(ip)

def get(domain_name): # by domain_name, ipv4 or ipv6
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

        print(existence_time.days)

if __name__ == "__main__":
    get("google.com")