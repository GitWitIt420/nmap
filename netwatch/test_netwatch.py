#!/usr/bin/env python3
"""Tests for netwatch.py.  Run: python3 -m unittest test_netwatch -v"""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import netwatch as nw

DAY = nw.DAY
T0 = 1_780_000_000  # a fixed "now" so the tests don't depend on the clock


def xml(*hosts):
    """Build nmap -oX output for (ip, mac, vendor) tuples."""
    parts = ['<?xml version="1.0"?><nmaprun>']
    for ip, mac, vendor in hosts:
        parts.append('<host><status state="up"/>'
                     '<address addr="%s" addrtype="ipv4"/>' % ip)
        if mac:
            parts.append('<address addr="%s" addrtype="mac" vendor="%s"/>'
                         % (mac, vendor))
        parts.append('</host>')
    parts.append('<host><status state="down"/>'
                 '<address addr="10.0.0.250" addrtype="ipv4"/></host>')
    parts.append('</nmaprun>')
    return "".join(parts)


ROUTER = ("192.168.1.1", "A0:AA:AA:00:00:01", "Netgear")
PHONE = ("192.168.1.20", "A0:AA:AA:00:00:02", "Apple")
STRANGER = ("192.168.1.66", "B0:BB:BB:00:00:66", "Espressif")
RANDOM = ("192.168.1.77", "DA:A1:19:00:00:77", "")


class NetwatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = nw.load_config(None)
        self.cfg["targets"] = "192.168.1.0/24"
        self.db = nw.open_db(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def scan(self, now, *hosts):
        path = os.path.join(self.tmp.name, "scan.xml")
        with open(path, "w") as f:
            f.write(xml(*hosts))
        with redirect_stdout(io.StringIO()):
            alerts = nw.do_scan(self.db, self.cfg, xml_file=path, now=now)
        return {(cat, dev["mac"]) for cat, dev, _, _ in alerts}

    def test_parse_skips_down_hosts(self):
        hosts = nw.parse_nmap_xml(xml(ROUTER, ("192.168.1.9", None, None)))
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["mac"], "a0:aa:aa:00:00:01")
        self.assertEqual(hosts[0]["vendor"], "Netgear")
        self.assertIsNone(hosts[1]["mac"])

    def test_first_scan_everything_is_new(self):
        got = self.scan(T0, ROUTER, PHONE)
        self.assertEqual({c for c, _ in got}, {"NEW"})

    def test_trusted_never_alerts(self):
        self.scan(T0, ROUTER, PHONE)
        with redirect_stdout(io.StringIO()):
            nw.do_trust_all_current(self.db)
        self.assertEqual(self.scan(T0 + DAY, ROUTER, PHONE), set())

    def test_trusted_from_config(self):
        self.cfg["trusted"] = {"a0:aa:aa:00:00:01": "router"}
        got = self.scan(T0, ROUTER, STRANGER)
        self.assertEqual(got, {("NEW", "b0:bb:bb:00:00:66")})

    def test_rare_device_alerts_with_cooldown(self):
        self.scan(T0, STRANGER)                       # NEW, alerted
        # 2 hours later: still inside the 12h cooldown -> quiet
        self.assertEqual(self.scan(T0 + 7200, STRANGER), set())
        # next day: rare, cooldown expired -> alert again
        self.assertEqual(self.scan(T0 + DAY, STRANGER),
                         {("RARE", "b0:bb:bb:00:00:66")})

    def test_frequent_device_stops_alerting(self):
        for day in range(20):
            got = self.scan(T0 + day * DAY, PHONE)
        self.assertEqual(got, set())

    def test_returning_after_a_month(self):
        self.scan(T0, STRANGER)
        self.assertEqual(self.scan(T0 + 45 * DAY, STRANGER),
                         {("RETURNING", "b0:bb:bb:00:00:66")})

    def test_bad_device_always_alerts(self):
        self.scan(T0, STRANGER)
        with redirect_stdout(io.StringIO()):
            nw.set_status(self.db, "B0-BB-BB-00-00-66", "bad", "neighbor")
        self.assertEqual(self.scan(T0 + DAY, STRANGER),
                         {("BAD", "b0:bb:bb:00:00:66")})

    def test_report_lists_only_untrusted(self):
        self.cfg["trusted"] = {"a0:aa:aa:00:00:01": "router"}
        self.scan(T0, ROUTER, STRANGER, RANDOM)
        csv_path = os.path.join(self.tmp.name, "r.csv")
        with redirect_stdout(io.StringIO()):
            rows = nw.do_report(self.db, self.cfg, csv_path, now=T0 + 60)
        macs = {r["mac"]: r for r in rows}
        self.assertEqual(set(macs), {"b0:bb:bb:00:00:66", "da:a1:19:00:00:77"})
        self.assertEqual(macs["da:a1:19:00:00:77"]["random_mac"], "yes")
        self.assertEqual(macs["b0:bb:bb:00:00:66"]["random_mac"], "")
        self.assertEqual(macs["b0:bb:bb:00:00:66"]["category"], "NEW-30D")
        self.assertTrue(os.path.exists(csv_path))

    def test_report_new_90d(self):
        self.scan(T0, STRANGER)
        with redirect_stdout(io.StringIO()):
            rows = nw.do_report(self.db, self.cfg, now=T0 + 50 * DAY)
        self.assertEqual(rows[0]["category"], "NEW-90D")

    def test_no_mac_falls_back_to_ip(self):
        got = self.scan(T0, ("192.168.1.5", None, None))
        self.assertEqual(got, {("NEW", None)})

    def test_message_mentions_random_mac(self):
        self.scan(T0, RANDOM)
        dev = self.db.execute("SELECT * FROM devices").fetchone()
        msg = nw.build_message([("NEW", dev, 1, 1)])
        self.assertIn("random MAC", msg)
        self.assertIn("192.168.1.77", msg)


if __name__ == "__main__":
    unittest.main()
