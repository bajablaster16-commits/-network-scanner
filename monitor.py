import subprocess, schedule, time, datetime, os
HOME_SUBNET = "192.168.4."
def get_current_ip():
    try:
        r = subprocess.run(["ipconfig","getifaddr","en0"], capture_output=True, text=True)
        return r.stdout.strip()
    except: return None
def on_home_network():
    ip = get_current_ip()
    return ip is not None and ip.startswith(HOME_SUBNET)
def run_scan():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = get_current_ip()
    if not on_home_network():
        print("[" + now + "] Not on home network (" + str(ip) + ") - skipping")
        return
    print("[" + now + "] On home network (" + str(ip) + ") - scanning...")
    os.system("sudo python3 ~/network-scanner/alerts.py")
    print("[" + now + "] Scan complete")
schedule.every().day.at("09:00").do(run_scan)
print("Monitor started - subnet: " + HOME_SUBNET)
print("Current IP: " + str(get_current_ip()))
print("On home network: " + str(on_home_network()))
run_scan()
print("Running - Ctrl+C to stop")
while True: schedule.run_pending(); time.sleep(60)