import base64
import requests
from dnslib import DNSRecord, QTYPE

def create_doh_query(domain):
    # Create a DNS query for an A record (IPv4 address)
    dns_query = DNSRecord.question(domain, QTYPE.A)
    
    # Base64 encode the DNS query
    dns_query_base64 = base64.urlsafe_b64encode(dns_query.pack()).decode('utf-8')
    
    return dns_query_base64

def send_doh_query(domain):
    # Prepare the DoH request
    dns_query_base64 = create_doh_query(domain)
    url = f"https://dns.google/dns-query?dns={dns_query_base64}"
    
    # Send the request
    response = requests.get(url)
    
    # Check for a valid response
    if response.status_code == 200:
        print(f"DoH Response for {domain}:")
        print(response.text)  # Print the raw DoH response (typically XML or JSON)
    else:
        print(f"Failed to fetch DoH data for {domain}. Status code: {response.status_code}")

# Test with a domain (e.g., google.com)
send_doh_query("google.com")
