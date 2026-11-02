"""Tests for the nmap XML parser.

Everything the agent believes about a target comes through _parse_nmap_xml, so a
silent parse regression turns into a false "0 open ports" — the most expensive kind
of wrong answer a scanner can give. Fixtures are real `nmap -oX` shapes; no nmap is run.
"""
from __future__ import annotations

import pytest

from pwner.tools import _parse_nmap_xml, _ports_arg_list, _summarize

SCAN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sV 10.0.0.5" start="1700000000">
<host starttime="1700000000" endtime="1700000060">
  <status state="up" reason="syn-ack" reason_ttl="127"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="web.lab" type="PTR"/></hostnames>
  <ports>
    <extraports state="filtered" count="996"/>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack" reason_ttl="64"/>
      <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      <script id="ssh-hostkey" output="  3072 SHA256:abcdef (RSA)"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack" reason_ttl="64"/>
      <service name="http" product="nginx" version="1.18.0" tunnel="ssl" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="closed" reason="reset" reason_ttl="64"/>
      <service name="mysql" method="table" conf="3"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.0 - 5.14" accuracy="95" line="62708"/>
    <osmatch name="Linux 4.15 - 5.8" accuracy="92" line="62132"/>
    <osmatch name="Linux 3.10" accuracy="90" line="60000"/>
    <osmatch name="Linux 2.6" accuracy="85" line="50000"/>
  </os>
  <hostscript>
    <script id="smb2-security-mode" output="Message signing enabled but not required"/>
  </hostscript>
</host>
</nmaprun>
"""

SWEEP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sn 10.0.0.0/30">
<host><status state="up" reason="arp-response"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
<host><status state="up" reason="echo-reply"/><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>
"""


def test_parses_ports_states_and_services():
    host = _parse_nmap_xml(SCAN_XML)["hosts"][0]
    assert host["status"] == "up"
    assert host["addresses"] == [{"addr": "10.0.0.5", "type": "ipv4"}]
    assert [(p["port"], p["state"]) for p in host["ports"]] == [(22, "open"), (443, "open"), (3306, "closed")]
    ssh = host["ports"][0]["service"]
    assert (ssh["name"], ssh["product"], ssh["version"]) == ("ssh", "OpenSSH", "8.9p1")
    assert host["ports"][1]["service"]["tunnel"] == "ssl"  # how HTTPS is distinguished


def test_port_id_is_an_int_not_a_string():
    """Port numbers are compared and range-checked downstream."""
    assert all(isinstance(p["port"], int) for p in _parse_nmap_xml(SCAN_XML)["hosts"][0]["ports"])


def test_parses_port_scripts_and_host_scripts():
    host = _parse_nmap_xml(SCAN_XML)["hosts"][0]
    assert host["ports"][0]["scripts"] == [{"id": "ssh-hostkey", "output": "3072 SHA256:abcdef (RSA)"}]
    assert host["hostscript"] == [
        {"id": "smb2-security-mode", "output": "Message signing enabled but not required"}]


def test_parses_os_matches():
    assert _parse_nmap_xml(SCAN_XML)["hosts"][0]["os"][0] == {"name": "Linux 5.0 - 5.14", "accuracy": "95"}


def test_host_with_no_ports_element_does_not_crash():
    """A -sn sweep emits no <ports>; the parser must still produce usable hosts."""
    hosts = _parse_nmap_xml(SWEEP_XML)["hosts"]
    assert [(h["addresses"][0]["addr"], h["status"]) for h in hosts] == [
        ("10.0.0.1", "up"), ("10.0.0.2", "down"), ("10.0.0.3", "up")]
    assert all(h["ports"] == [] for h in hosts)


def test_empty_scan_yields_no_hosts():
    assert _parse_nmap_xml('<?xml version="1.0"?><nmaprun scanner="nmap"/>') == {"hosts": []}


def test_malformed_xml_raises_rather_than_reporting_zero_hosts():
    import xml.etree.ElementTree as ET
    with pytest.raises(ET.ParseError):
        _parse_nmap_xml("nmap: command not found")


# ── _summarize ───────────────────────────────────────────────────────────────

def test_summarize_keeps_only_open_ports_by_default():
    host = _summarize(_parse_nmap_xml(SCAN_XML))["hosts"][0]
    assert [p["port"] for p in host["open_ports"]] == [22, 443]  # 3306 closed, dropped
    assert host["address"] == "10.0.0.5"


def test_summarize_can_keep_closed_ports():
    host = _summarize(_parse_nmap_xml(SCAN_XML), open_only=False)["hosts"][0]
    assert [p["port"] for p in host["open_ports"]] == [22, 443, 3306]


def test_summarize_caps_os_matches_at_three():
    """The fixture has four osmatch entries; the model gets the top three."""
    assert len(_summarize(_parse_nmap_xml(SCAN_XML))["hosts"][0]["os_matches"]) == 3


def test_summarize_preserves_down_hosts_for_ping_sweep():
    """ping_sweep filters on status == 'up', so summarize must not drop down hosts itself."""
    hosts = _summarize(_parse_nmap_xml(SWEEP_XML), open_only=False)["hosts"]
    assert [h["status"] for h in hosts] == ["up", "down", "up"]


# ── port selector -> nmap argv ───────────────────────────────────────────────

@pytest.mark.parametrize("selector,expected", [
    ("top-1000", ["--top-ports", "1000"]),
    ("top-100", ["--top-ports", "100"]),
    ("common", ["--top-ports", "1000"]),
    ("all", ["-p", "1-65535"]),
    ("TOP-100", ["--top-ports", "100"]),     # case-insensitive
    ("  all  ", ["-p", "1-65535"]),
    ("22,80,443", ["-p", "22,80,443"]),
    ("1-1024", ["-p", "1-1024"]),
    ("", []),                                 # empty -> nmap's own default
    (None, []),
])
def test_ports_arg_list(selector, expected):
    assert _ports_arg_list(selector) == expected
