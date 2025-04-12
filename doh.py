import requests

def test_doh(query, doh_url="https://dns.google/dns-query"):
    headers = {
        "Accept": "application/dns-json",
    }
    params = {
        "name": query,
        "type": "A"
    }
    try:
        # Send a DNS request over HTTPS
        response = requests.get(doh_url, headers=headers, params=params)
        response.raise_for_status()
        json_data = response.json()
        print(f"DoH Test: DNS result for {query}: {json_data}")
    except requests.exceptions.RequestException as e:
        print(f"Error with DoH test: {e}")

# Test DNS over HTTPS (DoH) for google.com
test_doh("google.com")
