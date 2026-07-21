# ============================================================
#   Simple Vulnerability Scanner
#   For learning purposes only — scan only your own systems
# ============================================================

import socket
import requests
import datetime

# Turn off SSL warnings
import urllib3
urllib3.disable_warnings()


# ── Settings ─────────────────────────────────────────────
PORTS_TO_CHECK = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet  ⚠ RISKY",
    80:   "HTTP",
    443:  "HTTPS",
    3306: "MySQL",
    3389: "RDP     ⚠ RISKY",
    8080: "HTTP-Alt",
    27017:"MongoDB ⚠ RISKY",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/phpmyadmin",
    "/backup.zip",
    "/robots.txt",
]


# ── Helper: print colored text ────────────────────────────
def ok(msg):   print("  [  OK  ]", msg)
def warn(msg): print("  [ WARN ]", msg)
def fail(msg): print("  [ RISK ]", msg)
def info(msg): print("  [ INFO ]", msg)


# ── Step 1: Scan Ports ────────────────────────────────────
def scan_ports(host):
    print("\n" + "="*50)
    print("  STEP 1: PORT SCAN")
    print("="*50)

    results = []

    for port, name in PORTS_TO_CHECK.items():
        try:
            s = socket.socket()
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            s.close()

            if result == 0:
                fail(f"Port {port} OPEN  → {name}")
                results.append(f"OPEN port {port} ({name})")
            else:
                ok(f"Port {port} closed → {name}")
        except:
            ok(f"Port {port} closed → {name}")

    return results


# ── Step 2: Check HTTP Headers ────────────────────────────
def check_headers(url):
    print("\n" + "="*50)
    print("  STEP 2: SECURITY HEADERS CHECK")
    print("="*50)

    results = []

    try:
        r = requests.get(url, timeout=5, verify=False)
        info(f"Connected to {url}  (Status: {r.status_code})")

        # Check each security header
        for header in SECURITY_HEADERS:
            if header in r.headers:
                ok(f"Header present   → {header}")
            else:
                fail(f"Header MISSING   → {header}")
                results.append(f"Missing header: {header}")

        # Check for server version leak
        server = r.headers.get("Server", "")
        if server:
            warn(f"Server info exposed → {server}")
            results.append(f"Server version exposed: {server}")

        x_powered = r.headers.get("X-Powered-By", "")
        if x_powered:
            warn(f"X-Powered-By exposed → {x_powered}")
            results.append(f"X-Powered-By exposed: {x_powered}")

        # HTTP warning
        if url.startswith("http://"):
            fail("Site uses HTTP (not HTTPS) — traffic is NOT encrypted")
            results.append("Site uses HTTP instead of HTTPS")

    except Exception as e:
        warn(f"Could not connect: {e}")

    return results


# ── Step 3: Check Sensitive Paths ─────────────────────────
def check_paths(base_url):
    print("\n" + "="*50)
    print("  STEP 3: SENSITIVE PATH CHECK")
    print("="*50)

    results = []

    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200:
                fail(f"EXPOSED [{r.status_code}] → {path}")
                results.append(f"Exposed path: {path}")
            elif r.status_code == 403:
                warn(f"Blocked [{r.status_code}] → {path}  (exists but restricted)")
            else:
                ok(f"Not found [{r.status_code}] → {path}")
        except:
            ok(f"No response → {path}")

    return results


# ── Step 4: Save Report ───────────────────────────────────
def save_report(target, port_issues, header_issues, path_issues):
    print("\n" + "="*50)
    print("  STEP 4: GENERATING REPORT")
    print("="*50)

    all_issues = port_issues + header_issues + path_issues
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = "vulnerability_report.txt"

    with open(filename, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("  VULNERABILITY SCAN REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"  Target    : {target}\n")
        f.write(f"  Date/Time : {now}\n")
        f.write(f"  Issues    : {len(all_issues)} found\n")
        f.write("=" * 50 + "\n\n")

        if all_issues:
            f.write("ISSUES FOUND:\n")
            for i, issue in enumerate(all_issues, 1):
                f.write(f"  {i}. {issue}\n")
        else:
            f.write("  No major issues found!\n")

        f.write("\n" + "=" * 50 + "\n")
        f.write("RECOMMENDATIONS:\n")
        f.write("  1. Close unused/risky ports (Telnet, RDP, MongoDB)\n")
        f.write("  2. Add all missing security headers to your web server\n")
        f.write("  3. Block access to sensitive paths via .htaccess or nginx\n")
        f.write("  4. Always use HTTPS instead of HTTP\n")
        f.write("  5. Never expose server version in headers\n")

    print(f"\n  Report saved → {filename}")
    print(f"  Total issues found: {len(all_issues)}")

    if len(all_issues) == 0:
        print("  Result: SAFE — No major issues detected!")
    elif len(all_issues) <= 3:
        print("  Result: LOW RISK — A few issues to fix.")
    elif len(all_issues) <= 6:
        print("  Result: MEDIUM RISK — Several issues need attention.")
    else:
        print("  Result: HIGH RISK — Many vulnerabilities found!")


# ── Main ──────────────────────────────────────────────────
def main():
    print("\n" + "="*50)
    print("   Simple Vulnerability Scanner")
    print("   For educational use only")
    print("="*50)

    # Ask user for target
    print("\n  Enter a URL to scan.")
    print("  Example: http://testphp.vulnweb.com")
    print("  (Press Enter to scan localhost)\n")

    target = input("  Your target: ").strip()

    if target == "":
        target = "http://127.0.0.1"

    if not target.startswith("http"):
        target = "http://" + target

    # Get just the hostname
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"\n  Scanning: {target}")
    print("  Please wait...\n")

    # Run all 3 checks
    port_issues   = scan_ports(host)
    header_issues = check_headers(target)
    path_issues   = check_paths(target)

    # Save report
    save_report(target, port_issues, header_issues, path_issues)

    print("\n  Done! Open vulnerability_report.txt to see full results.")
    print("="*50 + "\n")


# Run the program
main()
