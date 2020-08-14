import ssl
import json
import requests
import warnings
import os


API_Key = os.environ.get('VirusTotal_API')


'''Следующая функция принимает на вход путь к файлу и выдает значение типа float от 0 до 1(обозначим за res).
VirusTotal проверяет файл с помощью антивирусов и соответственно 
 res = количество антивирусов решивших, что файл подозрительный / на общее число антивирусов'''

def post_file_path_score(file_path):
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
    for i in response1:
        sum += response1[i]
    return float(score) / sum


'''Следующая функция принимает на вход хеш файла и выдает значение типа float от 0 до 1(обозначим за res).
VirusTotal проверяет файл с помощью антивирусов и соответственно 
 res = количество антивирусов решивших, что файл подозрительный / на общее число антивирусов'''

def get_file_hash_score(Hash_file):
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{Hash_file}", headers={"x-apikey": f"{API_Key}"})
    try:
        response.raise_for_status()
    except:
        raise Exception("Failed to connect to VirusTotal.")
    response = response.json()
    if ("error" in response):
        raise Exception(response['error']['message'])
    response1 = response['data']['attributes']['last_analysis_stats']
    score = response1['malicious']
    score += response1['suspicious']
    sum = 0
    for i in response1:
        sum += response1[i]
    return float(score) / sum


def print_pretty_json(data):
    print(json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False))