import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import nmap
import datetime

EMAIL = "jacobpolice4@gmail.com"
from dotenv import load_dotenv; load_dotenv()
APP_PASSWORD = os.getenv("APP_PASSWORD")
HISTORY_FILE = "device_history.json"

def identify_device(ports):
    p = list(ports)
    if 62078 in p and 5000 in p:
        return "MacBook / Mac Desktop"
    if 62078 in p:
        return "iPhone / iPad"
    if 8008 in p and 9000 in p:
        return "Google Chromecast / Home"
    if 9100 in p or 515 in p:
        return "Network Printer"
    if 53 in p and 1900 in p:
        return "Router / Gateway"
    if 53 in p and 3001 in p:
        return "DNS / Security Device"
    if 80 in p and 111 in p:
        return "Linux / NAS Device"
    if 5000 in p or 7000 in p:
        return "Apple Device / AirPlay"
    if 8080 in p or 9000 in p:
        return "Server / Camera System"
    if 3389 in p:
        return "Windows PC"
    if 22 in p:
        return "Linux / SSH Device"
    return "Unknown Device"

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return {}

def save_history(data):
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2)

def send_alert(all_devices, new_ips):
    msg = MIMEMultipart("alternative")
    new_count = len(new_ips)
    msg["Subject"] = f"🔍 Network Scan — {len(all_devices)} Devices ({new_count} New)"
    msg["From"] = EMAIL
    msg["To"] = EMAIL

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    body = f"""
    <html><body style="font-family:Arial;background:#1a1a2e;color:#eee;padding:20px;">
    <h2 style="color:#00d4ff;">🔍 Network Device Report</h2>
    <p style="color:#aaa;">Scan time: {now}</p>
    <table style="width:100%;border-collapse:collapse;margin-top:15px;">
      <tr style="background:#0f3460;">
        <th style="padding:10px;text-align:left;color:#00d4ff;">IP Address</th>
        <th style="padding:10px;text-align:left;color:#00d4ff;">Device Type</th>
        <th style="padding:10px;text-align:left;color:#00d4ff;">Times Seen</th>
        <th style="padding:10px;text-align:left;color:#00d4ff;">Status</th>
      </tr>
    """

    for device in all_devices:
        is_new = device["ip"] in new_ips
        status = '<span style="color:#e74c3c;font-weight:bold;">🆕 NEW</span>' if is_new else '<span style="color:#27ae60;">✅ Known</span>'
        times_seen = 0 if is_new else device["times_seen"]
        row_bg = "#1a1a3e" if is_new else "#16213e"

        body += f"""
      <tr style="background:{row_bg};border-bottom:1px solid #0f3460;">
        <td style="padding:10px;color:#00d4ff;">{device['ip']}</td>
        <td style="padding:10px;color:#ccc;">{device['device']}</td>
        <td style="padding:10px;color:#aaa;">#{times_seen}</td>
        <td style="padding:10px;">{status}</td>
      </tr>"""

    body += """
    </table>
    </body></html>
    """

    msg.attach(MIMEText(body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, APP_PASSWORD)
        server.sendmail(EMAIL, EMAIL, msg.as_string())

    print(f"   📧 Alert email sent to {EMAIL}")

def scan_and_alert(target):
    print(f"\nScanning {target}...")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments='--open')

    history = load_history()
    new_ips = []
    all_devices = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in scanner.all_hosts():
        ports = []
        for protocol in scanner[host].all_protocols():
            ports.extend(scanner[host][protocol].keys())

        device_type = identify_device(ports)

        if host not in history:
            print(f"   🆕 New device: {host} — {device_type}")
            new_ips.append(host)
            history[host] = {
                "first_seen": now,
                "last_seen": now,
                "times_seen": 0,
                "device": device_type,
                "ports": list(ports)
            }
        else:
            history[host]["times_seen"] = history[host].get("times_seen", 0) + 1
            history[host]["last_seen"] = now
            history[host]["device"] = device_type
            print(f"   ✅ Known device: {host} — {device_type} (seen #{history[host]['times_seen']})")

        all_devices.append({
            "ip": host,
            "device": device_type,
            "times_seen": history[host]["times_seen"],
            "ports": list(ports)
        })

    save_history(history)

    send_alert(all_devices, new_ips)

    print(f"\n✅ Scan complete!")
    print(f"   Total devices: {len(all_devices)}")
    print(f"   New devices:   {len(new_ips)}")

scan_and_alert("192.168.4.0/24")
