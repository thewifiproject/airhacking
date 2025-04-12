import httpx

def test_http2(url):
    try:
        # Create an HTTP/2 session with httpx
        with httpx.Client(http2=True) as client:
            response = client.get(url)
            print(f"HTTP/2 Test: {url} -> Status Code: {response.status_code}")
            print(f"Response Headers: {response.headers}")
    except Exception as e:
        print(f"Error with HTTP/2 test: {e}")

# Example URL (change this to a website that supports HTTP/2)
test_http2("https://www.google.com")
