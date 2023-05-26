import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import json
import requests


API_KEY = 'Your_Virustotal_API_key!!'
CACHE_FILE = 'scan_cache.json'

def calculate_file_hash(file_path):
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def scan_file_with_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

    response = requests.post(url, files=files, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            resource = json_response['resource']
            return resource
    return None

def retrieve_scan_report(resource, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    return None

def print_scan_result(scan_result):
    if scan_result['response_code'] == 1:
        result_text.insert(tk.END, "Scan Results:\n")
        result_text.insert(tk.END, "==============\n")
        result_text.insert(tk.END, "Scan Date: {}\n".format(scan_result['scan_date']))
        result_text.insert(tk.END, "Positives: {}\n".format(scan_result['positives']))
        result_text.insert(tk.END, "Total Scans: {}\n".format(scan_result['total']))
        result_text.insert(tk.END, "SHA256: {}\n".format(scan_result['sha256']))
        result_text.insert(tk.END, "MD5: {}\n".format(scan_result['md5']))
        result_text.insert(tk.END, "SHA1: {}\n".format(scan_result['sha1']))
        result_text.insert(tk.END, "Scan Results:\n")
        for antivirus, result in scan_result['scans'].items():
            result_text.insert(tk.END, "{}: {}\n".format(antivirus, result['result']))
    else:
        result_text.insert(tk.END, "Scan not available.\n")

def retrieve_file_metadata(file_path):
    file_metadata = {}
    if os.path.exists(file_path):
        file_metadata['File Size'] = os.path.getsize(file_path)
        file_metadata['File Type'] = os.path.splitext(file_path)[1]
        file_metadata['Creation Date'] = os.path.getctime(file_path)
        file_metadata['Last Modified Date'] = os.path.getmtime(file_path)
    return file_metadata

def load_scan_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_scan_cache(cache_data):
    with open(CACHE_FILE, 'w') as file:
        json.dump(cache_data, file)

def scan_file():
    file_path = file_entry.get()

    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File does not exist.")
        return

    file_hash = calculate_file_hash(file_path)
    scan_cache = load_scan_cache()

    if file_hash in scan_cache:
        scan_result = scan_cache[file_hash]
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Scan Result (Cached):\n")
        result_text.insert(tk.END, "======================\n")
        print_scan_result(scan_result)
    else:
        scan_result = retrieve_scan_report(file_hash, API_KEY)
        if scan_result is None:
            resource = scan_file_with_virustotal(file_path, API_KEY)
            if resource is None:
                messagebox.showerror("Error", "Error submitting the file for scanning.")
                return

            messagebox.showinfo("Info", "File submitted for scanning. Please wait for the results...")

            while True:
                scan_result = retrieve_scan_report(resource, API_KEY)
                if scan_result is not None:
                    break

            save_scan_cache({**scan_cache, file_hash: scan_result})

            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Scan Result:\n")
            result_text.insert(tk.END, "============\n")
            print_scan_result(scan_result)
        else:
            save_scan_cache({**scan_cache, file_hash: scan_result})

            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Scan Result (Cached):\n")
            result_text.insert(tk.END, "======================\n")
            print_scan_result(scan_result)

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(tk.END, file_path)


window = tk.Tk()
window.title("Malware Detection by Shubham_Gupta")
window.geometry("1000x1000")
window.configure(bg="#212121")

# Configure the color scheme
button_bg = "#2979FF"
button_fg = "#FFFFFF"
entry_bg = "#424242"
label_fg = "#FFFFFF"
result_text_bg = "#303030"
result_text_fg = "#FFFFFF"

# Define the banner text
banner_text = """
__     __     _           _      _                __  __       _                     
\ \   / /   _| |_ __   __| | ___| |_ _____  __   |  \/  | __ _| |___  ___ __ _ _ __  
 \ \ / / | | | | '_ \ / _` |/ _ \ __/ _ \ \/ /   | |\/| |/ _` | / __|/ __/ _` | '_ \ 
  \ V /| |_| | | | | | (_| |  __/ || (_) >  <    | |  | | (_| | \__ \ (_| (_| | | | |
   \_/  \__,_|_|_| |_|\__,_|\___|\__\___/_/\_\___|_|  |_|\__,_|_|___/\___\__,_|_| |_|
                                            |_____|                                  
                            +++++++++++++++++++++++++++++++++++++++              
                            |                                     |
                            |         Author: Shubham Gupta       |
                            |       Title: Malware Analysis       |
                            |         Created: May 2023           |
                            +++++++++++++++++++++++++++++++++++++++

"""

# Create the banner label
banner_label = tk.Label(
    window,
    text=banner_text,
    font=("Courier", 10, "bold"),
    justify="left",
    pady=8,
    fg="#FFFFFF",
    bg="#424242",
)
banner_label.pack(fill=tk.BOTH)

# Create the file selection section
file_label = tk.Label(window, text="File Path:", fg=label_fg, bg=window.cget("bg"))
file_label.pack()

file_entry = tk.Entry(window, width=100, bg=entry_bg, fg=label_fg)
file_entry.pack()

browse_button = tk.Button(
    window,
    text="Browse",
    command=browse_file,
    bg=button_bg,
    fg=button_fg,
    activebackground=button_bg,
    activeforeground=button_fg,
)
browse_button.pack(padx=5)

scan_button = tk.Button(
    window,
    text="Scan",
    command=scan_file,
    bg=button_bg,
    fg=button_fg,
    activebackground=button_bg,
    activeforeground=button_fg,
)
scan_button.pack(padx=5)

# Create the result display section
result_text = tk.Text(window, height=30, width=100, bg=result_text_bg, fg=result_text_fg, padx=5)
result_text.pack()

window.mainloop()
