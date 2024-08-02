import json
import requests


def fetch_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        'resultsPerPage': 10,
        'startIndex': 0,
        'pubStartDate': '2024-01-01T00:00:00:000 UTC-00:00',
        'pubEndDate': '2024-07-30T00:00:00:000 UTC-00:00'
    }
    headers = {
        'User-Agent': 'python-nvd-client'
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        print(response.json)
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None


cve_data = fetch_data()