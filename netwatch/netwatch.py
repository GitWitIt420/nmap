#!/usr/bin/env python3
"""
netwatch - watch your home network with nmap and text you about strangers.

Every scan is a fast nmap host-discovery sweep (-sn -T4).  Every device seen
is recorded in a small SQLite database, so netwatch knows how many different
days each device has shown up in the last 30 and 90 days.  Devices you have
confirmed are "trusted" and never alert.  Anything brand new, anything that
has only popped up a few times, and anything you have marked "bad" gets
texted to you.

Commands:
  netwatch.py scan              one scan, alert if needed (good for cron)
  netwatch.py watch             the listener: scan forever every N minutes
  netwatch.py report [--csv F]  list every device that isn't trusted
  netwatch.py trust MAC [LABEL] confirm a device is yours
  netwatch.py bad MAC [LABEL]   mark a device as not-yours (always alerts)
  netwatch.py forget MAC        clear trusted/bad status
  netwatch.py trust-all-current trust everything seen in the latest scan
  netwatch.py test-alert        send a test text message

Only uses the Python standard library.  Run as root (sudo) so nmap can do
ARP discovery and report MAC addresses; without MACs devices are tracked by IP.
"""

import argparse
import csv
import datetime as dt
import json
import os
import shutil
import smtplib
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from base64 import b64encode
from email.message import EmailMessage

DEFAULT_HOME = os.path.expanduser(os.environ.get("NETWATCH_HOME", "~/.netwatch"))

DEFAULT_CONFIG = {
    # Network to sweep.  "auto" reads the default route's interface subnet.
    "targets": "auto",
    # Extra nmap arguments.  -sn = no port scan, -T4 = fast timing.
    "nmap_args": ["-sn", "-T4", "-PR"],
    # Minutes between scans in "watch" mode.
    "interval_minutes": 5,
    # A device seen on at least this many different days in the last 30
    # days counts as a regular even if you haven't trusted it yet.
    "regular_min_days_30": 15,
    # A device seen on this many days or fewer in the last 90 days is "rare".
    "rare_max_days_90": 5,
    # Don't text about the same device more than once per this many hours.
    "alert_cooldown_hours": 12,
    # Drop sightings older than this to keep the database small.
    "keep_days": 120,
    # Your own devices: {"aa:bb:cc:dd:ee:ff": "Simone's phone"}.  You can
    # also use the "trust" command, which stores them in the database.
    "trusted": {},
    "notify": {
        # Any combination of: "twilio", "email_sms", "termux", "ntfy", "stdout"
        "methods": ["stdout"],
        "twilio": {
            "account_sid": "", "auth_token": "", "from": "", "to": ""
        },
        # Carrier email-to-SMS gateway, e.g. 5551234567@vtext.com (Verizon),
        # @txt.att.net (AT&T), @tmomail.net (T-Mobile).
        "email_sms": {
            "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "username": "", "password": "", "from": "", "to": ""
        },
        # Termux:API on Android: sends a real SMS from the phone.
        "termux": {"to": ""},
        # ntfy.sh push notification (free, no account needed).
        "ntfy": {"server": "https://ntfy.sh", "topic": ""}
    }
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    targets TEXT,
    host_count INTEGER
);
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY,          -- MAC address, or "ip:<addr>" if no MAC
    mac TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',   -- unknown | trusted | bad
    label TEXT,
    vendor TEXT,
    last_ip TEXT,
    hostname TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_alert INTEGER
);
CREATE TABLE IF NOT EXISTS sightings (
    scan_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    ts INTEGER NOT NULL,
    ip TEXT,
    PRIMARY KEY (scan_id, key)
);
CREATE INDEX IF NOT EXISTS sightings_key_ts ON sightings (key, ts);
"""

DAY = 86400


# --------------------------------------------------------------------------
# config / database

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path and os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
        for k, v in user.items():
            if k == "notify" and isinstance(v, dict):
                for nk, nv in v.items():
                    if isinstance(nv, dict):
                        cfg["notify"].setdefault(nk, {}).update(nv)
                    else:
                        cfg["notify"][nk] = nv
            else:
                cfg[k] = v
    cfg["trusted"] = {norm_mac(k): v for k, v in cfg.get("trusted", {}).items()}
    return cfg


def open_db(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def norm_mac(mac):
    return mac.strip().lower().replace("-", ":")


def is_randomized_mac(mac):
    """Phones use random 'private' MACs; the locally-administered bit is set."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


# --------------------------------------------------------------------------
# scanning

def detect_subnet():
    """Find the subnet of the interface that holds the default route."""
    try:
        out = subprocess.run(["ip", "-o", "-4", "route", "show", "default"],
                             capture_output=True, text=True).stdout.split()
        dev = out[out.index("dev") + 1]
        out = subprocess.run(["ip", "-o", "-4", "route", "show", "dev", dev,
                              "scope", "link"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            net = line.split()[0]
            if "/" in net:
                return net
    except (OSError, ValueError, IndexError):
        pass
    sys.exit("netwatch: could not detect your subnet; set \"targets\" "
             "in the config, e.g. \"192.168.1.0/24\"")


def run_nmap(targets, args):
    nmap = shutil.which("nmap")
    if not nmap:
        sys.exit("netwatch: nmap not found (apt install nmap / pkg install nmap)")
    cmd = [nmap] + list(args) + ["-oX", "-"] + targets.split()
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit("netwatch: nmap failed: %s" % res.stderr.strip())
    return res.stdout


def parse_nmap_xml(xml_text):
    """Return a list of {ip, mac, vendor, hostname} for hosts that are up."""
    hosts = []
    root = ET.fromstring(xml_text)
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        d = {"ip": None, "mac": None, "vendor": None, "hostname": None}
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not d["ip"]:
                d["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                d["mac"] = norm_mac(a.get("addr"))
                d["vendor"] = a.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            d["hostname"] = hn.get("name")
        if d["ip"] or d["mac"]:
            hosts.append(d)
    return hosts


# --------------------------------------------------------------------------
# recording + classification

def record_scan(db, cfg, hosts, targets, now):
    cur = db.execute("INSERT INTO scans (ts, targets, host_count) VALUES (?,?,?)",
                     (now, targets, len(hosts)))
    scan_id = cur.lastrowid
    for h in hosts:
        key = h["mac"] or "ip:" + h["ip"]
        row = db.execute("SELECT key FROM devices WHERE key=?", (key,)).fetchone()
        if row is None:
            status = "trusted" if h["mac"] in cfg["trusted"] else "unknown"
            db.execute("""INSERT INTO devices (key, mac, status, label, vendor,
                          last_ip, hostname, first_seen, last_seen)
                          VALUES (?,?,?,?,?,?,?,?,?)""",
                       (key, h["mac"], status, cfg["trusted"].get(h["mac"]),
                        h["vendor"], h["ip"], h["hostname"], now, now))
        else:
            db.execute("""UPDATE devices SET last_ip=?, last_seen=?,
                          vendor=COALESCE(?, vendor),
                          hostname=COALESCE(?, hostname) WHERE key=?""",
                       (h["ip"], now, h["vendor"], h["hostname"], key))
            if h["mac"] in cfg["trusted"]:
                db.execute("""UPDATE devices SET status='trusted',
                              label=COALESCE(label, ?)
                              WHERE key=? AND status='unknown'""",
                           (cfg["trusted"][h["mac"]], key))
        db.execute("INSERT OR IGNORE INTO sightings (scan_id, key, ts, ip) "
                   "VALUES (?,?,?,?)", (scan_id, key, now, h["ip"]))
    db.execute("DELETE FROM sightings WHERE ts < ?", (now - cfg["keep_days"] * DAY,))
    db.commit()
    return scan_id


def days_seen(db, key, since):
    return db.execute("""SELECT COUNT(DISTINCT date(ts, 'unixepoch', 'localtime'))
                         FROM sightings WHERE key=? AND ts>=?""",
                      (key, since)).fetchone()[0]


def classify(db, cfg, dev, now, scan_id):
    """Alert category for a device seen in scan_id.  Returns (cat, d30, d90).

    Categories, most to least suspicious:
      BAD        you marked it as not yours
      NEW        first time ever seen on the network
      RETURNING  seen before, but not once in the 30 days before this scan
      RARE       only seen on a few days in the last 90 days
      FREQUENT   shows up a lot but you haven't confirmed it yet
      TRUSTED    you confirmed it
    """
    d30 = days_seen(db, dev["key"], now - 30 * DAY)
    d90 = days_seen(db, dev["key"], now - 90 * DAY)
    if dev["status"] == "trusted":
        return "TRUSTED", d30, d90
    if dev["status"] == "bad":
        return "BAD", d30, d90
    prev = db.execute("SELECT MAX(ts) FROM sightings WHERE key=? AND scan_id<>?",
                      (dev["key"], scan_id)).fetchone()[0]
    if prev is None and dev["first_seen"] >= now:
        return "NEW", d30, d90
    if prev is not None and prev < now - 30 * DAY:
        return "RETURNING", d30, d90
    if d30 < cfg["regular_min_days_30"] and d90 <= cfg["rare_max_days_90"]:
        return "RARE", d30, d90
    return "FREQUENT", d30, d90


def report_category(db, cfg, dev, now):
    """Category for the report: when it first showed up and how often."""
    d30 = days_seen(db, dev["key"], now - 30 * DAY)
    d90 = days_seen(db, dev["key"], now - 90 * DAY)
    if dev["status"] == "trusted":
        return "TRUSTED", d30, d90
    if dev["status"] == "bad":
        return "BAD", d30, d90
    if dev["first_seen"] >= now - 30 * DAY:
        return "NEW-30D", d30, d90
    if dev["first_seen"] >= now - 90 * DAY:
        return "NEW-90D", d30, d90
    if d30 < cfg["regular_min_days_30"] and d90 <= cfg["rare_max_days_90"]:
        return "RARE", d30, d90
    return "FREQUENT", d30, d90


ALERT_CATEGORIES = ("BAD", "NEW", "RETURNING", "RARE")


def devices_to_alert(db, cfg, scan_id, now):
    out = []
    rows = db.execute("""SELECT d.* FROM devices d JOIN sightings s
                         ON s.key=d.key WHERE s.scan_id=?""", (scan_id,)).fetchall()
    for dev in rows:
        cat, d30, d90 = classify(db, cfg, dev, now, scan_id)
        if cat not in ALERT_CATEGORIES:
            continue
        cooldown = cfg["alert_cooldown_hours"] * 3600
        if cat != "NEW" and dev["last_alert"] and now - dev["last_alert"] < cooldown:
            continue
        out.append((cat, dev, d30, d90))
    order = {c: i for i, c in enumerate(ALERT_CATEGORIES)}
    out.sort(key=lambda t: order[t[0]])
    return out


def describe(dev):
    name = dev["label"] or dev["hostname"] or dev["vendor"] or "unknown vendor"
    mac = dev["mac"] or "no-mac"
    extra = " (random MAC)" if dev["mac"] and is_randomized_mac(dev["mac"]) else ""
    return "%s %s %s%s" % (dev["last_ip"], mac, name, extra)


def build_message(alerts):
    lines = ["NETWATCH: %d device(s) to check" % len(alerts)]
    for cat, dev, d30, d90 in alerts:
        lines.append("%s %s [%dd/30 %dd/90]" % (cat, describe(dev), d30, d90))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# notifications

def send_twilio(c, msg):
    url = ("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"
           % c["account_sid"])
    data = urllib.parse.urlencode({"From": c["from"], "To": c["to"],
                                   "Body": msg}).encode()
    req = urllib.request.Request(url, data=data)
    tok = b64encode(("%s:%s" % (c["account_sid"], c["auth_token"])).encode())
    req.add_header("Authorization", "Basic " + tok.decode())
    urllib.request.urlopen(req, timeout=30).read()


def send_email_sms(c, msg):
    em = EmailMessage()
    em["From"] = c["from"] or c["username"]
    em["To"] = c["to"]
    em["Subject"] = "netwatch"
    em.set_content(msg)
    with smtplib.SMTP(c["smtp_host"], int(c["smtp_port"]), timeout=30) as s:
        s.starttls()
        if c["username"]:
            s.login(c["username"], c["password"])
        s.send_message(em)


def send_termux(c, msg):
    subprocess.run(["termux-sms-send", "-n", c["to"], msg], check=True)


def send_ntfy(c, msg):
    url = "%s/%s" % (c["server"].rstrip("/"), c["topic"])
    req = urllib.request.Request(url, data=msg.encode(),
                                 headers={"Title": "netwatch",
                                          "Priority": "high"})
    urllib.request.urlopen(req, timeout=30).read()


SENDERS = {"twilio": send_twilio, "email_sms": send_email_sms,
           "termux": send_termux, "ntfy": send_ntfy}


def notify(cfg, msg):
    """Send msg through every configured method.  Returns True if any worked."""
    sms = msg if len(msg) <= 600 else msg[:597] + "..."
    ok = False
    for method in cfg["notify"]["methods"]:
        if method == "stdout":
            print(msg)
            ok = True
            continue
        try:
            SENDERS[method](cfg["notify"][method], sms)
            ok = True
        except Exception as e:  # keep the listener alive no matter what
            print("netwatch: %s notification failed: %s" % (method, e),
                  file=sys.stderr)
    return ok


# --------------------------------------------------------------------------
# commands

def do_scan(db, cfg, xml_file=None, now=None):
    now = int(now or time.time())
    targets = cfg["targets"]
    if targets == "auto" and not xml_file:
        targets = detect_subnet()
    if xml_file:
        with open(xml_file) as f:
            xml_text = f.read()
    else:
        xml_text = run_nmap(targets, cfg["nmap_args"])
    hosts = parse_nmap_xml(xml_text)
    if hosts and not any(h["mac"] for h in hosts):
        print("netwatch: warning: no MAC addresses in scan; run as root "
              "so devices can be told apart reliably", file=sys.stderr)
    scan_id = record_scan(db, cfg, hosts, targets, now)
    alerts = devices_to_alert(db, cfg, scan_id, now)
    stamp = dt.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    print("[%s] %d host(s) up, %d alert(s)" % (stamp, len(hosts), len(alerts)))
    if alerts and notify(cfg, build_message(alerts)):
        db.executemany("UPDATE devices SET last_alert=? WHERE key=?",
                       [(now, dev["key"]) for _, dev, _, _ in alerts])
        db.commit()
    return alerts


def do_watch(db, cfg):
    interval = max(1, int(cfg["interval_minutes"])) * 60
    print("netwatch: listening, scanning every %d min (Ctrl-C to stop)"
          % (interval // 60))
    while True:
        try:
            do_scan(db, cfg)
        except SystemExit as e:
            print(e, file=sys.stderr)
        except Exception as e:
            print("netwatch: scan error: %s" % e, file=sys.stderr)
        time.sleep(interval)


def fmt_ts(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


def do_report(db, cfg, csv_path=None, show_all=False, now=None):
    now = int(now or time.time())
    rows = []
    for dev in db.execute("SELECT * FROM devices ORDER BY last_seen DESC"):
        cat, d30, d90 = report_category(db, cfg, dev, now)
        if cat == "TRUSTED" and not show_all:
            continue
        rows.append({
            "category": cat, "mac": dev["mac"] or "", "ip": dev["last_ip"] or "",
            "name": dev["label"] or dev["hostname"] or "",
            "vendor": dev["vendor"] or "",
            "random_mac": "yes" if dev["mac"] and is_randomized_mac(dev["mac"]) else "",
            "days_30": d30, "days_90": d90,
            "first_seen": fmt_ts(dev["first_seen"]),
            "last_seen": fmt_ts(dev["last_seen"]),
        })
    order = {c: i for i, c in enumerate(
        ("BAD", "NEW-30D", "NEW-90D", "RARE", "FREQUENT", "TRUSTED"))}
    rows.sort(key=lambda r: (order[r["category"]], r["days_90"]))
    if csv_path:
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["category"])
            w.writeheader()
            w.writerows(rows)
        print("wrote %d device(s) to %s" % (len(rows), csv_path))
    if not rows:
        print("No unconfirmed devices.  Everything seen is trusted.")
        return rows
    cols = ["category", "mac", "ip", "vendor", "name", "random_mac",
            "days_30", "days_90", "first_seen", "last_seen"]
    width = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("  ".join(c.upper().ljust(width[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(width[c]) for c in cols))
    print("\nConfirm yours with:  netwatch.py trust <MAC> \"label\"")
    print("Flag strangers with: netwatch.py bad <MAC> \"label\"")
    return rows


def set_status(db, mac, status, label=None):
    key = norm_mac(mac)
    cur = db.execute("UPDATE devices SET status=?, label=COALESCE(?, label) "
                     "WHERE key=? OR mac=?", (status, label, key, key))
    db.commit()
    if cur.rowcount == 0:
        sys.exit("netwatch: no device %s in the database yet" % key)
    print("%s -> %s%s" % (key, status, " (%s)" % label if label else ""))


def do_trust_all_current(db):
    last = db.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    if last is None:
        sys.exit("netwatch: no scans yet; run 'scan' first")
    cur = db.execute("""UPDATE devices SET status='trusted' WHERE status='unknown'
                        AND key IN (SELECT key FROM sightings WHERE scan_id=?)""",
                     (last,))
    db.commit()
    print("trusted %d device(s) from the latest scan" % cur.rowcount)


def main(argv=None):
    p = argparse.ArgumentParser(description="nmap network watcher with text alerts")
    p.add_argument("-c", "--config", default=os.path.join(DEFAULT_HOME, "config.json"))
    p.add_argument("--db", default=os.path.join(DEFAULT_HOME, "netwatch.db"))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan once and alert")
    s.add_argument("--xml-file", help="use an existing nmap -oX file instead of scanning")
    sub.add_parser("watch", help="scan forever (the listener)")
    r = sub.add_parser("report", help="list devices that are not trusted")
    r.add_argument("--csv", help="also write the list to a CSV file")
    r.add_argument("--all", action="store_true", help="include trusted devices")
    for name in ("trust", "bad"):
        t = sub.add_parser(name)
        t.add_argument("mac")
        t.add_argument("label", nargs="?")
    f = sub.add_parser("forget", help="reset a device to unknown")
    f.add_argument("mac")
    sub.add_parser("trust-all-current", help="trust everything in the latest scan")
    sub.add_parser("test-alert", help="send a test text")
    a = p.parse_args(argv)

    cfg = load_config(a.config)
    db = open_db(a.db)
    if a.cmd == "scan":
        do_scan(db, cfg, a.xml_file)
    elif a.cmd == "watch":
        do_watch(db, cfg)
    elif a.cmd == "report":
        do_report(db, cfg, a.csv, a.all)
    elif a.cmd == "trust":
        set_status(db, a.mac, "trusted", a.label)
    elif a.cmd == "bad":
        set_status(db, a.mac, "bad", a.label)
    elif a.cmd == "forget":
        set_status(db, a.mac, "unknown")
    elif a.cmd == "trust-all-current":
        do_trust_all_current(db)
    elif a.cmd == "test-alert":
        if not notify(cfg, "NETWATCH test: text alerts are working."):
            sys.exit("netwatch: no notification method succeeded")


if __name__ == "__main__":
    main()
