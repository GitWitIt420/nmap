# netwatch: nmap device watcher with text alerts

netwatch sweeps your home network with nmap (`-sn -T4 -PR`) and records every device it sees in a small SQLite database. If a device is brand new, has only shown up a few times, comes back after a month away, or is one you flagged as bad, netwatch texts you.

It only uses the Python 3 standard library plus `nmap`.

## How it decides what's "weird"

netwatch counts the number of **distinct days** each device has been on the network in the last **30** and **90** days.

| Category    | Meaning                                                            | Texts you?            |
|-------------|--------------------------------------------------------------------|-----------------------|
| `BAD`       | You marked it with `netwatch.py bad`                               | yes (every cooldown)  |
| `NEW`       | First time it has ever been seen                                   | yes, immediately      |
| `RETURNING` | Seen before, but not once in the past 30 days                      | yes                   |
| `RARE`      | Seen on 5 or fewer days in the last 90 days (`rare_max_days_90`)   | yes (every cooldown)  |
| `FREQUENT`  | Shows up a lot but you haven't confirmed it                        | no                    |
| `TRUSTED`   | You confirmed it (`trust` command or `"trusted"` in the config)    | never                 |

`alert_cooldown_hours` (default 12) stops it texting about the same device on every scan.

The report (`netwatch.py report`) lists every device that isn't trusted. Devices first seen in the last month are tagged `NEW-30D`, and devices first seen in the last three months are tagged `NEW-90D`. The report also shows how many days each device was seen in each window. You can use it to go through the list and confirm which devices are yours.

**Random MACs:** iPhones, Android phones and Windows laptops often use a "private" (randomized) MAC address per network. The report and the texts mark these devices `random MAC`. A phone whose MAC changes looks like a new device. To stop that for your family's phones, turn off "Private Wi-Fi address" for your home network on each phone, then trust the phone.

## Quick start (Kali / Debian / Raspberry Pi)

```bash
sudo apt install nmap python3
cd netwatch
sudo mkdir -p /root/.netwatch
sudo cp config.example.json /root/.netwatch/config.json
sudo nano /root/.netwatch/config.json     # set targets + your phone number

sudo ./netwatch.py test-alert             # make sure the text arrives
sudo ./netwatch.py scan                   # first scan: everything is NEW
sudo ./netwatch.py report                 # see what's on your network
sudo ./netwatch.py trust aa:bb:cc:dd:ee:ff "Simone's phone"
sudo ./netwatch.py trust-all-current      # or: trust everything seen right now
sudo ./netwatch.py watch                  # the listener: scans every 5 min
```

Run it as root (`sudo`). nmap needs root to ARP-scan and read MAC addresses. Without MAC addresses, netwatch can only track devices by IP, which is far less reliable.

### Run the listener 24/7

As a systemd service (survives reboots):

```bash
sudo cp netwatch.py /usr/local/bin/
sudo cp netwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch
journalctl -u netwatch -f
```

Or with cron, scanning every 5 minutes (`sudo crontab -e`):

```
*/5 * * * * /usr/bin/python3 /usr/local/bin/netwatch.py scan >> /var/log/netwatch.log 2>&1
```

## Text message setup

Set `notify.methods` in the config to one or more of the following methods:

* **`email_sms`**: Free. Sends an email to your carrier's SMS gateway: Verizon `5551234567@vtext.com`, AT&T `@txt.att.net`, T-Mobile `@tmomail.net`. With Gmail, use an [App Password](https://myaccount.google.com/apppasswords), not your normal password.
* **`twilio`**: Real SMS through the Twilio API. Fill in `account_sid`, `auth_token`, `from` (your Twilio number) and `to`.
* **`termux`**: If netwatch runs on an Android phone with Termux and Termux:API (`pkg install termux-api`), it sends a real SMS from that phone with `termux-sms-send`. Android doesn't let unrooted apps read MAC addresses, so use this on a rooted phone, or run the scanner on a Pi/Kali box.
* **`ntfy`**: Free push notification to the ntfy app. Pick a long, random topic name, because anyone who knows the topic can read the alerts.
* **`stdout`**: Just prints the alert (handy for logs and testing).

A text looks like this:

```
NETWATCH: 2 device(s) to check
NEW 192.168.1.66 b0:bb:bb:00:00:66 Espressif [1d/30 1d/90]
RARE 192.168.1.77 da:a1:19:00:00:77 unknown vendor (random MAC) [2d/30 3d/90]
```

## Commands

```
netwatch.py scan [--xml-file F]  scan once (or load an nmap -oX file) and alert
netwatch.py watch                the listener: scan every interval_minutes
netwatch.py report [--csv F] [--all]
netwatch.py trust MAC [LABEL]    confirm a device is yours
netwatch.py bad MAC [LABEL]      flag a device as not yours (always alerts)
netwatch.py forget MAC           reset a device to unknown
netwatch.py trust-all-current    trust every device in the latest scan
netwatch.py test-alert           send a test text
```

Files live in `~/.netwatch/` (`/root/.netwatch/` under sudo). Set `NETWATCH_HOME` to change that, or use `-c` / `--db`.

## Tests

```bash
cd netwatch && python3 -m unittest test_netwatch -v
```
