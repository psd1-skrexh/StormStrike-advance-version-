import socket, requests, os, time, random
from urllib.parse import urlparse
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from termcolor import colored

init(autoreset=True)

def slow_print(text, delay=0.02):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.CYAN + figlet_format("Web Recon", font="slant"))
    print(Fore.YELLOW + "-" * 60)
    slow_print(Fore.LIGHTGREEN_EX + "Developer: Parvez | Use Only For Ethical Purposes!", 0.01)
    print(Fore.YELLOW + "-" * 60)

def animated_input(prompt):
    colors = [Fore.RED, Fore.GREEN, Fore.BLUE, Fore.CYAN, Fore.YELLOW]
    color = random.choice(colors)
    return input(color + prompt + Fore.RESET)

def get_domain_from_input(user_input):
    if not user_input.startswith("http"):
        user_input = "http://" + user_input
    parsed = urlparse(user_input)
    return parsed.netloc

def get_ip_port(domain):
    slow_print(Fore.MAGENTA + "\n[+] Finding IP & Open Ports...")
    try:
        ip = socket.gethostbyname(domain)
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        return ip, open_ports
    except Exception as e:
        return "Error", []

def detect_firewall(domain):
    slow_print(Fore.MAGENTA + "\n[+] Detecting Firewall / WAF...")
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get("http://" + domain, headers=headers, timeout=3)
        server = r.headers.get("Server", "Unknown")
        wafs = ["cloudflare", "sucuri", "incapsula", "akamai", "f5", "waf", "mod_security"]
        detected = "None"
        for keyword in wafs:
            if keyword in r.text.lower() or keyword in server.lower():
                detected = keyword.upper()
                break
        return server, detected
    except:
        return "N/A", "Detection Failed"

def ddos_check(ports):
    slow_print(Fore.MAGENTA + "\n[+] Estimating DDoS Risk Level...")
    if 80 in ports or 443 in ports:
        return colored("Moderate Risk (Web server exposed)", "yellow")
    elif len(ports) == 0:
        return colored("Low Risk (Ports Closed or Protected)", "green")
    else:
        return colored("Unusual Port Config (Check Manually)", "cyan")

def print_result(title, value, color="white"):
    print(Fore.LIGHTBLUE_EX + f"\n[{title}]: " + getattr(Fore, color.upper(), Fore.WHITE) + str(value))

def main():
    banner()
    user_input = animated_input("Enter website (e.g. https://example.com): ")
    domain = get_domain_from_input(user_input)

    ip, ports = get_ip_port(domain)
    print_result("Target Domain", domain, "green")
    print_result("IP Address", ip, "yellow")
    print_result("Open Ports", ports if ports else "No Open Ports", "red" if not ports else "green")

    server, firewall = detect_firewall(domain)
    print_result("Server Info", server, "cyan")
    print_result("Firewall/WAF", firewall, "magenta")

    ddos_risk = ddos_check(ports)
    print(Fore.LIGHTYELLOW_EX + f"\n[DDoS Vulnerability]: {ddos_risk}")

    print(Fore.LIGHTGREEN_EX + "\n[✓] Scan Complete.")

if __name__ == "__main__":
    main()
