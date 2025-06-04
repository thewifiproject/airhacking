import argparse
import sqlite3
import hashlib
import os
import sys

def pbkdf2_hex(passphrase, ssid, iterations=4096, dklen=32):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), iterations, dklen).hex()

def db_init(dbfile):
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS ssids (id INTEGER PRIMARY KEY, ssid TEXT UNIQUE)')
    c.execute('CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, password TEXT UNIQUE)')
    c.execute('''CREATE TABLE IF NOT EXISTS pmks (
        id INTEGER PRIMARY KEY,
        ssid_id INTEGER,
        password_id INTEGER,
        pmk TEXT,
        UNIQUE(ssid_id, password_id),
        FOREIGN KEY (ssid_id) REFERENCES ssids(id),
        FOREIGN KEY (password_id) REFERENCES passwords(id)
    )''')
    conn.commit()
    return conn

def import_essid(conn, essid_file):
    c = conn.cursor()
    with open(essid_file, encoding='utf-8', errors='ignore') as f:
        for line in f:
            ssid = line.strip()
            if ssid:
                try:
                    c.execute("INSERT OR IGNORE INTO ssids(ssid) VALUES (?)", (ssid,))
                except Exception as e:
                    print(f"Error inserting SSID: {ssid}: {e}")
    conn.commit()

def import_passwd(conn, passwd_file):
    c = conn.cursor()
    with open(passwd_file, encoding='utf-8', errors='ignore') as f:
        for line in f:
            pwd = line.strip()
            if pwd:
                try:
                    c.execute("INSERT OR IGNORE INTO passwords(password) VALUES (?)", (pwd,))
                except Exception as e:
                    print(f"Error inserting password: {pwd}: {e}")
    conn.commit()

def batch_compute(conn):
    c = conn.cursor()
    c.execute("SELECT id, ssid FROM ssids")
    ssids = c.fetchall()
    c.execute("SELECT id, password FROM passwords")
    passes = c.fetchall()
    total = len(ssids) * len(passes)
    done = 0
    for ssid_id, ssid in ssids:
        for pass_id, password in passes:
            c.execute("SELECT 1 FROM pmks WHERE ssid_id=? AND password_id=?", (ssid_id, pass_id))
            if c.fetchone():
                continue
            pmk = pbkdf2_hex(password, ssid)
            c.execute("INSERT OR IGNORE INTO pmks(ssid_id,password_id,pmk) VALUES (?,?,?)", (ssid_id, pass_id, pmk))
            done += 1
            if done % 100 == 0:
                print(f"Computed {done}/{total} PMKs...")
    conn.commit()
    print(f"Batch PMK computation complete. {done} new PMKs computed.")

def stats(conn):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM ssids")
    n_ssid = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM passwords")
    n_pass = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM pmks")
    n_pmks = c.fetchone()[0]
    print(f"SSIDs: {n_ssid}")
    print(f"Passwords: {n_pass}")
    print(f"PMKs: {n_pmks}")

def verify(conn):
    c = conn.cursor()
    c.execute("SELECT pmks.id, ssids.ssid, passwords.password, pmks.pmk FROM pmks JOIN ssids ON pmks.ssid_id=ssids.id JOIN passwords ON pmks.password_id=passwords.id")
    errors = 0
    for rowid, ssid, password, pmk in c.fetchall():
        calc = pbkdf2_hex(password, ssid)
        if pmk != calc:
            print(f"Invalid PMK entry for SSID '{ssid}' and password '{password}'.")
            errors += 1
    if errors == 0:
        print("All PMK entries are correct.")
    else:
        print(f"{errors} invalid PMK entries found.")

def clean(conn):
    c = conn.cursor()
    # Remove PMKs referencing non-existent ssids/passwords
    c.execute("DELETE FROM pmks WHERE ssid_id NOT IN (SELECT id FROM ssids) OR password_id NOT IN (SELECT id FROM passwords)")
    conn.commit()
    print("Cleaned unused PMK entries.")

def export_cowpatty(conn, out_file):
    # Output: ssid:password:pmk
    c = conn.cursor()
    c.execute('''SELECT ssids.ssid, passwords.password, pmks.pmk
        FROM pmks
        JOIN ssids ON pmks.ssid_id=ssids.id
        JOIN passwords ON pmks.password_id=passwords.id''')
    with open(out_file, "w") as f:
        for ssid, password, pmk in c.fetchall():
            f.write(f"{ssid}:{password}:{pmk}\n")
    print(f"Exported data to {out_file}.")

def main():
    parser = argparse.ArgumentParser(description="airvault: WPA/WPA2 PMK precomputation DB like airolib-ng")
    parser.add_argument("db", help="Database file")
    parser.add_argument("--import", dest="import_type", nargs=2, metavar=('type', 'file'),
                        help="Import SSIDs or passwords (type: essid|passwd)")
    parser.add_argument("--batch", action="store_true", help="Compute all missing PMKs")
    parser.add_argument("--stats", action="store_true", help="Show stats")
    parser.add_argument("--verify", action="store_true", help="Verify correctness of PMKs")
    parser.add_argument("--clean", action="store_true", help="Clean unused entries")
    parser.add_argument("--export-cowpatty", metavar="FILE", help="Export database to coWPAtty format")
    args = parser.parse_args()

    conn = db_init(args.db)

    if args.import_type:
        if args.import_type[0] == "essid":
            import_essid(conn, args.import_type[1])
            print("Imported ESSIDs.")
        elif args.import_type[0] == "passwd":
            import_passwd(conn, args.import_type[1])
            print("Imported passwords.")
        else:
            print("Unknown import type. Use 'essid' or 'passwd'.")
            sys.exit(1)
    if args.batch:
        batch_compute(conn)
    if args.stats:
        stats(conn)
    if args.verify:
        verify(conn)
    if args.clean:
        clean(conn)
    if args.export_cowpatty:
        export_cowpatty(conn, args.export_cowpatty)
    if not any([args.import_type, args.batch, args.stats, args.verify, args.clean, args.export_cowpatty]):
        parser.print_help()

if __name__ == "__main__":
    main()
