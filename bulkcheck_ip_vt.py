import requests

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = 'insert api key here'

def check_ip_reputation(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if 'data' in result:
            if 'attributes' in result['data']:
                attributes = result['data']['attributes']
                print(f"IP Address: {ip_address}")
                print(f"Last Analysis Stats: {attributes['last_analysis_stats']}")
                print("----------")
            else:
                print(f"No attributes found for IP Address: {ip_address}")
        else:
            print(f"No data found for IP Address: {ip_address}")
    else:
        print(f"Failed to retrieve data for IP Address: {ip_address}")

# Read IP addresses from the input file
with open('input.txt', 'r') as file:
    ip_addresses = file.read().splitlines()

for ip in ip_addresses:
    check_ip_reputation(ip)
