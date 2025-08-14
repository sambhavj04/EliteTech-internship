import socket
import requests

# -------------------------------
# Port Scanner Module
# -------------------------------
def scan_ports(target_ip, ports):
    print(f"\n[+] Scanning ports on {target_ip}...")
    open_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

    return open_ports

# -------------------------------
# Banner Grabber Module
# -------------------------------
def grab_banner(ip, port):
    print(f"\n[+] Grabbing banner from {ip}:{port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception as e:
        return f"Error: {e}"

# -------------------------------
# HTTP Brute-Forcer Module
# -------------------------------
def http_brute_force(url, username, wordlist_path):
    print(f"\n[+] Starting brute-force on {url} with username '{username}'...")
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            passwords = [line.strip() for line in file if line.strip()]

        for password in passwords:
            try:
                response = requests.get(url, auth=(username, password), timeout=5)
                if response.status_code == 200:
                    print(f"[✓] Password found: {password}")
                    return
                else:
                    print(f"[✗] Tried: {password}")
            except requests.RequestException as req_err:
                print(f"[!] Request error: {req_err}")
                break

        print("[-] Password not found in wordlist.")
    except FileNotFoundError:
        print(f"[!] Wordlist file '{wordlist_path}' not found.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

# -------------------------------
# Main CLI Interface
# -------------------------------
def main():
    print("\n=== 🛠️ Penetration Testing Toolkit ===")
    print("1. Port Scanner")
    print("2. Banner Grabber")
    print("3. HTTP Brute-Forcer")
    print("0. Exit")

    choice = input("Select a module: ").strip()

    if choice == "1":
        target = input("Enter target IP: ").strip()
        ports = input("Enter ports (comma-separated): ").strip()
        try:
            ports = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            print("[!] Invalid port numbers.")
            return
        open_ports = scan_ports(target, ports)
        print(f"\n[+] Open ports: {open_ports if open_ports else 'None'}")

    elif choice == "2":
        ip = input("Enter target IP: ").strip()
        try:
            port = int(input("Enter port: ").strip())
        except ValueError:
            print("[!] Invalid port number.")
            return
        banner = grab_banner(ip, port)
        print(f"\n[+] Banner: {banner}")

    elif choice == "3":
        url = input("Enter target URL (e.g., http://example.com): ").strip()
        username = input("Enter username: ").strip()
        wordlist = input("Enter path to wordlist file: ").strip()
        http_brute_force(url, username, wordlist)

    elif choice == "0":
        print("Exiting... Goodbye!")
    else:
        print("[!] Invalid choice.")

if __name__ == "__main__":
    main()

