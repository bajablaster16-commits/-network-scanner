import subprocess

def get_current_wifi():
    try:
        result = subprocess.run(
            ["ipconfig", "getsummary", "en0"],
            capture_output=True, text=True
        )
        for line in result.stdout.split("\n"):
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    except:
        return None
    return None

print(f"Detected WiFi: {get_current_wifi()}")
