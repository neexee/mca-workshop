import ssl
import json
import requests
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
ssl._create_default_https_context = ssl._create_unverified_context

HOST_SITE = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
API_key =  "at_bVMpAvJB5O1MsbYS1uVErw2BaW7ot"

def print_pretty_json(data):
    print(json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False))

def get(domain_name): # by domain_name, ipv4 or ipv6
    try:
        request = requests.get(f"{HOST_SITE}?apiKey={API_key}&domainName={domain_name}&outputFormat=JSON&ip=1",
                               verify=False)
        data = request.json()
        request.raise_for_status()
        return data
    except Exception as exc:
        print(exc)