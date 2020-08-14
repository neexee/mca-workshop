import requests


def enrich_events(events, showlog=True):
    for event in events:
        if event.EventId == 1:
            event.Score = get_file_hash_score(event.Details['Hash'])
            if showlog:
                print(event.EventId,
                      event.ProcessName,
                      event.User,
                      event.Host,
                      event.Details,
                      'hash_score = {}'.format(event.Score))
        if event.EventId == 3:
            event.Score = get_ip_score(event.Details['IP_address'])
            if showlog:
                print(event.EventId,
                      event.ProcessName,
                      event.User,
                      event.Host,
                      event.Details,
                      'ip_score = {}'.format(event.Score))


VT_API_KEY = "4c4834cb97799f86ad590b2e917228468af9353026c825fb47269e56e6075fe9"


def get_file_hash_score(file_hash):
    """
    Принимает на вход хеш файла и выдает значение типа float от 0 до 1(обозначим за res).
    VirusTotal проверяет файл с помощью 61го антивируса и соответственно
     res = количество антивирусов решивших, что файл малварь / на общее число антивирусов(61)'''
    """
    response = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": f"{VT_API_KEY}"})
    try:
        response.raise_for_status()
    except Exception as err:
        raise Exception("VirusTotal API error") from err
    content = response.json()

    if "error" in content:
        raise Exception(content['error']['message'])
    r = content['data']['attributes']['last_analysis_stats']
    score = r['malicious'] + 0.5 * r['suspicious']
    return score


def get_ip_score(ip):
    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": f"{VT_API_KEY}"})
    response.raise_for_status()
    content = response.json()

    if "error" in content:
        raise Exception(content['error']['message'])
    r = content['data']['attributes']['last_analysis_stats']
    score = r['malicious'] + 0.5 * r['suspicious']
    return score


def get_file_score(file_path):
    with open(file_path, 'r') as file_content:
        response = requests.post("https://www.virustotal.com/api/v3/files",
                                 headers={"x-apikey": f"{VT_API_KEY}"},
                                 files={"file": file_content})
    try:
        response.raise_for_status()
    except Exception as err:
        raise Exception("Failed to connect to VirusTotal") from err
    response = response.json()
    if "error" in response:
        raise Exception(response['error']['message'])
    id = response['data']['id']
    response1 = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{id}",
        headers={"x-apikey": f"{VT_API_KEY}"})
    try:
        response1.raise_for_status()
    except Exception as err:
        raise Exception("Failed to connect to VirusTotal") from err
    response1 = response1.json()
    if "error" in response:
        raise Exception(response1['error']['message'])
    response1 = response1['data']['attributes']['stats']
    score = response1['malicious']
    score += response1['suspicious']

    return float(score)
