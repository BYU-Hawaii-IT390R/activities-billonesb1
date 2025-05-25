# ✅ Windows Admin Toolkit – Fully Annotated Version
# --------------------------------------------------
# This script includes several Windows admin tools,
# with detailed comments for clarity.

from __future__ import annotations  # Allow forward references in type hints
import argparse  # Command-line argument parsing
import collections  # Provides Counter and defaultdict
import csv  # For optional CSV export of installed software
import datetime as _dt  # For working with dates and times
import io  # For handling in-memory streams (used in CSV parsing)
import re  # For regex matching (IP extraction, etc.)
import subprocess  # For running Windows command-line tools
import sys  # For system exit and error reporting
from pathlib import Path  # File path utilities
from xml.etree import ElementTree as ET  # XML parsing of event logs

# Try importing Windows-only libraries
try:
    import win32evtlog  # Required for reading the Security Event Log
    import winreg  # Used to access the Windows Registry
except ImportError:
    sys.stderr.write("pywin32 required → pip install pywin32\n")
    sys.exit(1)  # Stop execution if Windows modules are not available

# Constants used to identify relevant event log types
SECURITY_CHANNEL = "Security"
EVENT_FAILED = "4625"
EVENT_SUCCESS = "4624"
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")  # Match IPv4 addresses

# Terminal color codes for service status output
COLOR_OK = "\033[92m"   # Green
COLOR_BAD = "\033[91m"  # Red
COLOR_RESET = "\033[0m"  # Reset to default color

# Function to print a dictionary (like Counter) in a table format
def _print_counter(counter: dict, h1: str, h2: str):
    if not counter:
        print("(no data)\n")
        return
    width = max(len(str(k)) for k in counter)  # Determine column width
    print(f"{h1:<{width}} {h2:>8}")
    print("-" * (width + 9))
    for k, v in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        print(f"{k:<{width}} {v:>8}")
    print()

# Function to query recent logon events from the Event Log
def _query_security_xml(hours_back: int):
    delta_sec = hours_back * 3600  # Convert hours to seconds
    q = (
        f"*[(System/TimeCreated[timediff(@SystemTime) <= {delta_sec}] "
        f"and (System/EventID={EVENT_FAILED} or System/EventID={EVENT_SUCCESS}))]"
    )
    try:
        h = win32evtlog.EvtQuery(SECURITY_CHANNEL, win32evtlog.EvtQueryReverseDirection, q)
    except Exception as e:
        if getattr(e, "winerror", None) == 5:
            sys.exit("❌ Access denied – run as Administrator or add to *Event Log Readers* group.")
        raise
    while True:
        try:
            ev = win32evtlog.EvtNext(h, 1)[0]
        except IndexError:
            break
        yield win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)

# Function to extract event ID, user, and IP address from XML string
def _parse_event(xml_str: str):
    root = ET.fromstring(xml_str)
    eid = root.findtext("./System/EventID")
    data = {n.attrib.get("Name"): n.text for n in root.findall("./EventData/Data")}
    user = data.get("TargetUserName") or data.get("SubjectUserName") or "?"
    ip = data.get("IpAddress") or "?"
    if ip == "?":
        m = IP_RE.search(xml_str)
        if m:
            ip = m.group()
    return eid, user, ip

# Main task to summarize logon events
def win_events(hours_back: int, min_count: int):
    failed = collections.Counter()
    success = collections.defaultdict(set)
    for xml_str in _query_security_xml(hours_back):
        eid, user, ip = _parse_event(xml_str)
        if eid == EVENT_FAILED and ip != "?":
            failed[ip] += 1
        elif eid == EVENT_SUCCESS and user not in ("-", "?"):
            success[user].add(ip)
    print(f"\n❌ Failed logons ≥{min_count} (last {hours_back}h)")
    _print_counter({ip: c for ip, c in failed.items() if c >= min_count}, "Source IP", "Count")
    print(f"✅ Successful logons ≥{min_count} IPs (last {hours_back}h)")
    succ = {u: ips for u, ips in success.items() if len(ips) >= min_count}
    width = max((len(u) for u in succ), default=8)
    print(f"{'Username':<{width}} {'IPs':>8}")
    print("-" * (width + 9))
    for user, ips in sorted(succ.items(), key=lambda item: len(item[1]), reverse=True):
        print(f"{user:<{width}} {len(ips):>8}")
    print()

# Registry paths to check for installed applications
UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

# Task to list installed software and optionally export to CSV
def win_pkgs(csv_path: str | None):
    rows: list[tuple[str, str]] = []
    for root, path in UNINSTALL_PATHS:
        try:
            hive = winreg.OpenKey(root, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(hive)[0]):
            try:
                sub = winreg.OpenKey(hive, winreg.EnumKey(hive, i))
                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                ver, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                rows.append((name, ver))
            except FileNotFoundError:
                continue
    print(f"\n🗃 Installed software ({len(rows)} entries)")
    width = max(len(n) for n, _ in rows)
    print(f"{'DisplayName':<{width}} Version")
    print("-" * (width + 8))
    for name, ver in sorted(rows):
        print(f"{name:<{width}} {ver}")
    print()
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"📑 CSV exported → {csv_path}\n")

# Function to get the state of a Windows service
def _service_state(name: str) -> str:
    out = subprocess.check_output(["sc", "query", name], text=True, stderr=subprocess.STDOUT)
    return "RUNNING" if "RUNNING" in out else "STOPPED"

# Task to monitor and optionally fix stopped services
def win_services(watch: list[str], auto_fix: bool):
    if not watch:
        watch = ["Spooler", "wuauserv"]
    print("\n🩺 Service status")
    for svc in watch:
        state = _service_state(svc)
        ok = state == "RUNNING"
        colour = COLOR_OK if ok else COLOR_BAD
        print(f"{svc:<20} {colour}{state}{COLOR_RESET}")
        if not ok and auto_fix:
            print(f"  ↳ attempting to start {svc} …", end="")
            subprocess.call(["sc", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state = _service_state(svc)
            print("done" if state == "RUNNING" else "failed")
    print()

# Task to list all non-Microsoft scheduled tasks
def win_tasks():
    print("\n🕒 Scheduled Tasks (non-Microsoft)")
    try:
        output = subprocess.check_output(["schtasks", "/query", "/fo", "CSV", "/v"], text=True)
    except subprocess.CalledProcessError:
        print("❌ Failed to query scheduled tasks.")
        return
    import csv
    from io import StringIO
    reader = csv.DictReader(StringIO(output))
    tasks = []
    for row in reader:
        name = row.get("TaskName", "")
        author = row.get("Author", "")
        next_run = row.get("Next Run Time", "")
        status = row.get("Status", "")
        if "Microsoft" not in author and name:
            tasks.append((name, next_run, status))
    if not tasks:
        print("(no non-Microsoft tasks found)\n")
        return
    width = max(len(t[0]) for t in tasks)
    print(f"{'Task Name':<{width}} {'Next Run':>25} {'Status':>15}")
    print("-" * (width + 42))
    for name, next_run, status in sorted(tasks):
        print(f"{name:<{width}} {next_run:>25} {status:>15}")
    print()

# Task to display startup programs from registry
def win_startup():
    # Print a heading to indicate this task is about startup programs
    print("\n🚀 Startup Programs")
    # Define the registry paths to check for startup entries
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM")
    ]
    entries = []
    for root, path, hive in paths:
        try:
            key = winreg.OpenKey(root, path)
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, val, _ = winreg.EnumValue(key, i)
                entries.append((name, val, hive))
        except FileNotFoundError:
            continue
    if not entries:
        print("(no startup items found)\n")
        return
    width = max(len(name) for name, _, _ in entries)
    print(f"{'Name':<{width}} {'Source':<6} Path")
    print("-" * (width + 30))
    for name, path, hive in sorted(entries):
        print(f"{name:<{width}} {hive:<6} {path}")
    print()

# CLI parser to run selected task from command line
def main():
    p = argparse.ArgumentParser(description="Windows admin toolkit (IT 390R)")
    p.add_argument("--task", required=True,
                   choices=["win-events", "win-pkgs", "win-services", "win-tasks", "win-startup"],
                   help="Which analysis to run")
    p.add_argument("--hours", type=int, default=24,
                   help="Look-back window for Security log (win-events)")
    p.add_argument("--min-count", type=int, default=1,
                   help="Min occurrences before reporting (win-events)")
    p.add_argument("--csv", metavar="FILE", default=None,
                   help="Export installed-software list to CSV (win-pkgs)")
    p.add_argument("--watch", nargs="*", metavar="SVC", default=[],
                   help="Service names to check (win-services)")
    p.add_argument("--fix", action="store_true",
                   help="Attempt to start stopped services (win-services)")

    args = p.parse_args()

    if args.task == "win-events":
        win_events(args.hours, args.min_count)
    elif args.task == "win-pkgs":
        win_pkgs(args.csv)
    elif args.task == "win-services":
        win_services(args.watch, args.fix)
    elif args.task == "win-tasks":
        win_tasks()
    elif args.task == "win-startup":
        win_startup()

# Entry point of the script
if __name__ == "__main__":
    main()