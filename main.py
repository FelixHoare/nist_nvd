import json
import requests
import pandas as pd


def fetch_data(results):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'resultsPerPage': results,
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
        cves = data['vulnerabilities']
        formatted_data = []
        for item in cves:
            cve = item.get('cve', {})

            cve_id = cve.get('id', '')
            descriptions = cve.get('descriptions', [])
            description = 'No description available'
            published = cve.get('published', '')
            lastModified = cve.get('lastModified', '')
            severity = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('baseSeverity', 'N/A')
            )
            userInteraction = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('userInteractionRequired', 'N/A')
            )
            auth = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('cvssData', {})
                .get('authentication', 'N/A')
            )
            confidentiality = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('cvssData', {})
                .get('confidentialityImpact', 'N/A')
            )
            integrity = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('cvssData', {})
                .get('integrityImpact', 'N/A')
            )
            availability = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('cvssData', {})
                .get('availabilityImpact', 'N/A')
            )
            allPriv = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('obtainAllPrivilege', 'N/A')
            )
            userPriv = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('obtainUserPrivilege', 'N/A')
            )
            otherPriv = (
                cve.get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('obtainOtherPrivilege', 'N/A')
            )

            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', description)
                    break

            cve_info = {
                'cve_id': cve_id,
                'description': description,
                'severity': severity,
                'userInteraction': userInteraction,
                'authentication': auth,
                'confidentialityImpact': confidentiality,
                'integrityImpact': integrity,
                'availabilityImpact': availability,
                'obtainAllPrivilege': allPriv,
                'obtainUserPrivilege': userPriv,
                'obtainOtherPrivilege': otherPriv,
                'published': published,
                'lastModified': lastModified,
            }
            # cve_info = {
            #     'id': cve['cve']['id'],
            #     'description': cve['cve']['descriptions']['lang' == 'en']['value'],
            #     'severity': cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
            #     'publishedDate': cve['cve']['published'],
            #     'lastModified': cve['cve']['lastModified']
            # }
            formatted_data.append(cve_info)
        return formatted_data


def print_cve(data):
    for item in data:
        print(f"CVE ID: {item['cve_id']}")
        print(f"Description: {item['description']}")
        print(f"Severity: {item['severity']}")
        print(f"User interaction required?: {item['userInteraction']}")
        print(f"Authentication required?: {item['authentication']}")
        print(f"Confidentiality impacted?: {item['confidentialityImpact']}")
        print(f"Integrity impacted?: {item['integrityImpact']}")
        print(f"Availability impacted?: {item['availabilityImpact']}")
        print(f"Obtain all privilege?: {item['obtainAllPrivilege']}")
        print(f"Obtain user privilege?: {item['obtainUserPrivilege']}")
        print(f"Obtain other privilege?: {item['obtainOtherPrivilege']}")
        print(f"Published Date: {item['published']}")
        print(f"Last Modified Date: {item['lastModified']}")
        print("-" * 80)


def save_to_excel(data, filename='cve_data.xlsx'):
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print(f"Excel file saved to {filename}")


while True:
    numResults = input("How many results would you like to see? (Between 1 and 259059) ")
    try:
        numResults = int(numResults)
        break
    except ValueError:
        print("Please enter a valid number.")

cve_data = fetch_data(numResults)

formatted_data = format_data(cve_data)

if formatted_data:
    print("-" * 80)
    print_cve(formatted_data)
    save_to_excel(formatted_data)
else:
    print("No data available to save")

