import json
import requests


def fetch_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'resultsPerPage': 1,
        'startIndex': 0,
        #'pubStartDate': '2024-01-01T00:00:00:000 UTC-00:00',
        #'pubEndDate': '2024-07-30T00:00:00:000 UTC-00:00'
    }
    headers = {
        'User-Agent': 'python-nvd-client'
    }
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        try:
            return response.json()
        except json.JSONDecodeError:
            print("Error: Response content is not valid JSON")
            print(response.text)
            return None
    elif response.status_code == 404:
        print("Error 404: The requested resource was not found. Please check the URL and parameters.")
        print(response.text)
        return None
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None


def format_data(data):
    if data:
        #print(data)
        cves = data['vulnerabilities']
        #print(cves)
        formatted_data = []
        for cve in cves:
            cve_info = {
                'id': cve['cve']['id'],
                'description': cve['cve']['descriptions'][0]['value'],
                'publishedDate': cve['cve']['published'],
                'lastModified': cve['cve']['lastModified']
            }
            formatted_data.append(cve_info)
        return formatted_data


cve_data = fetch_data()


formatted_data = format_data(cve_data)


for item in formatted_data:
    print(f"CVE ID: {item['id']}")
    print(f"Description: {item['description']}")
    print(f"Published Date: {item['publishedDate']}")
    print(f"Last Modified Date: {item['lastModified']}")
    print("-" * 80)
