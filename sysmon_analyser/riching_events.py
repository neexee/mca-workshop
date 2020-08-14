'''from typing import List, Tuple, Iterable
from datatypes.datatypes import Event

def riching_events(events):
    for event in events:
        event.Score = 0.0
    return events
'''
import ssl
import json
import requests
import warnings
import os
from datetime import date
import math
import dateutil.parser


'''Следующая функция принимает на вход хеш файла и выдает значение типа float от 0 до 1(обозначим за res).
VirusTotal проверяет файл с помощью 61го антивируса и соответственно 
 res = количество антивирусов решивших, что файл малварь / на общее число антивирусов(61)'''

def get_file_hash_score(Hash_file):
    API_Key= "4c4834cb97799f86ad590b2e917228468af9353026c825fb47269e56e6075fe9"
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{Hash_file}", headers={"x-apikey": f"{API_Key}"})
    try:
        response.raise_for_status()
    except:
        raise Exception("Не удалось подключиться к VirusTotal.")
    response = response.json()
    
    if ("error" in response):
        raise Exception(response['error']['message'])
    r = response['data']['attributes']['last_analysis_stats']
    score = r['malicious']+0.5*r['suspicious'] 
    return score

def get_ip_score(ip):
    API_Key= "4c4834cb97799f86ad590b2e917228468af9353026c825fb47269e56e6075fe9"
    response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": f"{API_Key}"})
    response.raise_for_status()
    response = response.json()
    
    if ("error" in response):
        raise Exception(response['error']['message'])
    r = response['data']['attributes']['last_analysis_stats']
    score = r['malicious']+0.5*r['suspicious'] 
    return score

def get_file_score(file_path):
    API_Key= "4c4834cb97799f86ad590b2e917228468af9353026c825fb47269e56e6075fe9"
    myfile = {"file": open(f"{file_path}", 'r')}
    response = requests.post("https://www.virustotal.com/api/v3/files",
                             headers={"x-apikey": f"{API_Key}"},
                             files=myfile)
    try:
        response.raise_for_status()
    except:
        raise Exception("Failed to connect to VirusTotal.")
    response = response.json()
    if ("error" in response):
        raise Exception(response['error']['message'])
    id = response['data']['id']
    response1 = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers={"x-apikey": f"{API_Key}"})
    try:
        response1.raise_for_status()
    except:
        raise Exception("Failed to connect to VirusTotal.")
    response1 = response1.json()
    if ("error" in response):
        raise Exception(response1['error']['message'])
    response1 = response1['data']['attributes']['stats']
    score = response1['malicious']
    score += response1['suspicious']
    sum = 0
    return float(score)

if (__name__ == '__main__'):
    my_ip = '67.199.248.10'
    my_hash = '29c3831337fef3513ebeff1de40057c8'
    print(my_ip, get_ip_score(my_ip))
    print(my_hash, get_file_hash_score(my_hash))