import nmap
import datetime
import requests
import time

def get_cves(service_name, port):
    if not service_name or service_name in ["tcpwrapped", "-", ""]:
        return []
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cves = data if isinstance(data, list) else data.get("results", [])
            result = []
            for cve in cves[:3]:
                cve_id = cve.get("id", "N/A")
                summary = cve.get("summary", "No description")[:120]
                cvss = cve.get("cvss", "N/A")
                result.append({"id": cve_id, "summary": summary, "cvss": cvss})
            return result
    except:
        return []
    return []

def identify_device(ports):
    port_list = list(ports)
    if 8008 in port_list and 9000 in port_list:
        return "Google Chromecast / Home Device"
    if 62078 in port_list:
        return "Apple iOS Device (iPhone/iPad)"
    if 9100 in port_list or 515 in port_list:
        return "Network Printer"
    if 53 in port_list and 1900 in port_list:
        return "Router / Gateway"
    if 53 in port_list and 3001 in port_list:
        return "DNS Device / Security Tool"
    if 80 in port_list and 111 in port_list:
        return "Linux / NAS Device"
    if 5000 in port_list or 7000 in port_list:
        return "Apple Mac / AirPlay Device"
    if 8080 in port_list or 9000 in port_list:
        return "Server / NVR / Camera System"
    return "Unknown Device"

def risk_score(ports, device):
    score = 0
    risky_ports = {
        21: 30, 23: 40, 3389: 30, 9100: 25,
        515: 20, 111: 20, 8080: 10, 4000: 15,
        9999: 15, 5555: 20, 1900: 10
    }
    for port in ports:
        score += risky_ports.get(port, 2)
    if "Printer" in device:
        score += 20
    if "Unknown" in device:
        score += 10
    return min(score, 100)

def risk_label(score):
    if score >= 50:
        return "HIGH", "#e74c3c"
    elif score >= 25:
        return "MEDIUM", "#f39c12"
    else:
        return "LOW", "#27ae60"

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f"\nScanning {target}...")
    scanner.scan(hosts=target, arguments='-sV --open')

    hosts_data = []

    for host in scanner.all_hosts():
        ports = []
        for protocol in scanner[host].all_protocols():
            for port in scanner[host][protocol].keys():
                service = scanner[host][protocol][port]
                ports.append({
                    "port": port,
                    "name": service["name"],
                    "version": service["version"]
                })

        port_nums = [p["port"] for p in ports]
        device = identify_device(port_nums)
        score = risk_score(port_nums, device)
        label, color = risk_label(score)

        hosts_data.append({
            "ip": host,
            "device": device,
            "ports": ports,
            "score": score,
            "label": label,
            "color": color
        })

    hosts_data.sort(key=lambda x: x["score"], reverse=True)

    print("\n🔍 Looking up CVEs for discovered services...")
    for h in hosts_data:
        for p in h["ports"]:
            print(f"   Checking {p['name']} on port {p['port']}...")
            p["cves"] = get_cves(p["name"], p["port"])
            time.sleep(0.5)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network Scan Report</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 30px; }}
  h1 {{ color: #00d4ff; }}
  .meta {{ color: #aaa; margin-bottom: 30px; }}
  .host {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #00d4ff; }}
  .host-header {{ display: flex; justify-content: space-between; align-items: center; }}
  .ip {{ font-size: 1.3em; font-weight: bold; color: #00d4ff; }}
  .device {{ color: #ccc; margin-top: 4px; }}
  .badge {{ padding: 6px 14px; border-radius: 20px; font-weight: bold; color: white; font-size: 0.9em; }}
  .score {{ color: #aaa; font-size: 0.85em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 14px; }}
  th {{ background: #0f3460; color: #00d4ff; padding: 8px; text-align: left; }}
  td {{ padding: 8px; border-bottom: 1px solid #0f3460; vertical-align: top; }}
  .flag {{ color: #e74c3c; font-weight: bold; }}
  .cve-box {{ background: #0f3460; border-radius: 6px; padding: 8px; margin-top: 6px; font-size: 0.8em; }}
  .cve-id {{ color: #00d4ff; font-weight: bold; }}
  .cve-score {{ color: #f39c12; }}
  .cve-summary {{ color: #ccc; }}
  .summary {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 30px; }}
  .summary h2 {{ color: #00d4ff; }}
  .stat {{ display: inline-block; margin-right: 30px; }}
  .stat-num {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
  .stat-label {{ color: #aaa; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>🔍 Network Scan Report</h1>
<div class="meta">Target: {target} &nbsp;|&nbsp; Scan Date: {now}</div>

<div class="summary">
  <h2>Summary</h2>
  <div class="stat"><div class="stat-num">{len(hosts_data)}</div><div class="stat-label">Hosts Found</div></div>
  <div class="stat"><div class="stat-num">{sum(1 for h in hosts_data if h['label'] == 'HIGH')}</div><div class="stat-label">High Risk</div></div>
  <div class="stat"><div class="stat-num">{sum(1 for h in hosts_data if h['label'] == 'MEDIUM')}</div><div class="stat-label">Medium Risk</div></div>
  <div class="stat"><div class="stat-num">{sum(1 for h in hosts_data if h['label'] == 'LOW')}</div><div class="stat-label">Low Risk</div></div>
</div>
"""

    risky_ports_flag = {21, 23, 3389, 9100, 515, 111, 5555, 9999, 4000, 1900}

    for h in hosts_data:
        html += f"""
<div class="host">
  <div class="host-header">
    <div>
      <div class="ip">{h['ip']}</div>
      <div class="device">📱 {h['device']}</div>
      <div class="score">Risk Score: {h['score']}/100</div>
    </div>
    <div class="badge" style="background:{h['color']}">{h['label']} RISK</div>
  </div>
  <table>
    <tr><th>Port</th><th>Service</th><th>Version</th><th>Flag</th><th>Known CVEs</th></tr>
"""
        for p in h["ports"]:
            flag = '<span class="flag">⚠️ RISKY</span>' if p["port"] in risky_ports_flag else "✅ OK"
            cve_html = ""
            if p.get("cves"):
                for cve in p["cves"]:
                    cve_html += f"""
                    <div class="cve-box">
                        <span class="cve-id">{cve['id']}</span>
                        <span class="cve-score"> | CVSS: {cve['cvss']}</span><br>
                        <span class="cve-summary">{cve['summary']}...</span>
                    </div>"""
            else:
                cve_html = '<span style="color:#aaa">None found</span>'

            html += f"    <tr><td>{p['port']}</td><td>{p['name']}</td><td>{p['version'] or '-'}</td><td>{flag}</td><td>{cve_html}</td></tr>\n"

        html += "  </table>\n</div>\n"

    html += "</body></html>"

    with open("scan_report.html", "w") as f:
        f.write(html)

    total_cves = sum(len(p.get("cves", [])) for h in hosts_data for p in h["ports"])

    print("\n✅ Scan complete!")
    print(f"   Hosts found:  {len(hosts_data)}")
    print(f"   High risk:    {sum(1 for h in hosts_data if h['label'] == 'HIGH')}")
    print(f"   CVEs found:   {total_cves}")
    print(f"   Report saved to scan_report.html")
    print("\n   Open it with: open scan_report.html")

scan_network("192.168.4.0/24")
