"""
HoneyGuard Local Attack Simulation & Testing Suite
=============================================================================
⚠️ STRICT SAFETY WARNING:
This script is strictly intended for educational evaluation and viva demos.
It connects ONLY to the local HoneyGuard decoy (127.0.0.1:2222).
NEVER execute attack scripts against networks or servers you do not own!
=============================================================================
"""

import sys
import time
import socket
from pathlib import Path
import paramiko
import config

TARGET_HOST = "127.0.0.1"
TARGET_PORT = config.HONEYPOT_PORT

def print_header(title: str):
    print("\n" + "="*65)
    print(f"🎯 [SIMULATION] {title}")
    print("="*65)

def test_single_login(username: str = "support", password: str = "TestPass123"):
    """Tests basic honeypot authentication denial."""
    print_header("Test 1: Single Honeypot Authentication Attempt")
    print(f"Connecting to {TARGET_HOST}:{TARGET_PORT} as '{username}'...")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=TARGET_HOST,
            port=TARGET_PORT,
            username=username,
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False
        )
        print("❌ UNEXPECTED: Connection authorized! (Honeypot should never allow login)")
    except paramiko.AuthenticationException:
        print(f"✅ SUCCESS: Honeypot rejected password as expected (Access Denied).")
        print(f"   Credentials logged: User='{username}', Pass='{password}'")
    except Exception as exc:
        print(f"⚠️ Connection error: {exc}")
    finally:
        ssh.close()

def test_brute_force(count: int = 6):
    """Simulates a rapid SSH brute force attack against a single username."""
    print_header(f"Test 2: Brute Force Attack Simulation ({count} attempts in <10s)")
    passwords = [
        "123456", "password", "admin123", "root2024", "toor", "letmein123", "welcome1"
    ]
    target_user = "admin"

    print(f"Targeting '{target_user}' with {count} dictionary passwords...")

    for i in range(count):
        pwd = passwords[i % len(passwords)]
        print(f"[{i+1}/{count}] Trying '{target_user}':'{pwd}'...", end=" ", flush=True)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=TARGET_HOST,
                port=TARGET_PORT,
                username=target_user,
                password=pwd,
                timeout=3,
                allow_agent=False,
                look_for_keys=False
            )
        except paramiko.AuthenticationException:
            print("Denied 🛑")
        except Exception as e:
            print(f"Error ({e})")
        finally:
            ssh.close()
        time.sleep(0.4)

    print("\n👉 Check your Dashboard or Terminal: 'BRUTE_FORCE' alert should have triggered!")

def test_credential_stuffing(count: int = 5):
    """Simulates credential stuffing by trying multiple distinct usernames."""
    print_header(f"Test 3: Credential Stuffing Simulation ({count} distinct usernames)")
    usernames = ["root", "ubuntu", "postgres", "cisco", "oracle", "manager"]
    default_pwd = "P@ssw0rd2024!"

    for i in range(min(count, len(usernames))):
        user = usernames[i]
        print(f"[{i+1}/{count}] Testing credentials for '{user}'...", end=" ", flush=True)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=TARGET_HOST,
                port=TARGET_PORT,
                username=user,
                password=default_pwd,
                timeout=3,
                allow_agent=False,
                look_for_keys=False
            )
        except paramiko.AuthenticationException:
            print("Denied 🛑")
        except Exception as e:
            print(f"Error ({e})")
        finally:
            ssh.close()
        time.sleep(0.4)

    print("\n👉 Check your Dashboard or Terminal: 'CREDENTIAL_STUFFING' alert should have triggered!")

def test_port_scan(burst_count: int = 7):
    """Simulates rapid TCP connections to test the port sweep detection rule."""
    print_header(f"Test 4: TCP Port Scan / Rapid Probe Simulation ({burst_count} touches)")
    print(f"Initiating {burst_count} rapid socket handshakes on port {TARGET_PORT}...")

    for i in range(burst_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((TARGET_HOST, TARGET_PORT))
            print(f"[{i+1}/{burst_count}] TCP SYN-ACK handshake established.", flush=True)
            sock.close()
        except Exception as exc:
            print(f"[{i+1}/{burst_count}] Connection: {exc}")
        time.sleep(0.2)

    print("\n👉 Check your Dashboard or Terminal: 'PORT_SCAN' alert should have triggered!")

def test_canary_tamper():
    """Simulates an intruder finding and modifying the decoy canary file."""
    print_header("Test 5: Canary Honeytoken Tamper Trigger")
    canary_path = config.CANARY_FILE_PATH
    if not canary_path.exists():
        import canary
        canary.create_decoy_canary_file()

    print(f"Accessing canary honeytoken at: {canary_path}")
    try:
        # Simulate touch/write to trigger file watchdog
        with open(canary_path, "a+b") as f:
            f.write(b" ")
        print("✅ Canary file touched and modified.")
        print("👉 Watch the dashboard: Instant CRITICAL Canary Breach alert triggered!")
    except Exception as exc:
        print(f"⚠️ Could not tamper canary file: {exc}")

def run_menu():
    print("""
===========================================================
🍯 HONEYGUARD ATTACK SIMULATOR (VIVA & LAB TESTING)
===========================================================
Target: 127.0.0.1 (Local Decoy Only)
Select an intrusion test:
  [1] Single SSH Auth Check (Standard Rejection)
  [2] Simulate Brute-Force Attack (6 Rapid Passwords)
  [3] Simulate Credential Stuffing (5 Distinct Usernames)
  [4] Simulate Rapid Port Probe / Sweep
  [5] Simulate Canary Honeytoken Breach (passwords.xlsx)
  [6] Run ALL Tests Sequentially
  [0] Exit
===========================================================
""")
    choice = input("Enter option [0-6]: ").strip()
    if choice == "1":
        test_single_login()
    elif choice == "2":
        test_brute_force()
    elif choice == "3":
        test_credential_stuffing()
    elif choice == "4":
        test_port_scan()
    elif choice == "5":
        test_canary_tamper()
    elif choice == "6":
        test_single_login()
        time.sleep(1)
        test_brute_force()
        time.sleep(1)
        test_credential_stuffing()
        time.sleep(1)
        test_port_scan()
        time.sleep(1)
        test_canary_tamper()
    elif choice == "0":
        print("Exiting test suite.")
        sys.exit(0)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        test_single_login()
        time.sleep(1)
        test_brute_force()
        time.sleep(1)
        test_credential_stuffing()
        time.sleep(1)
        test_port_scan()
        time.sleep(1)
        test_canary_tamper()
    else:
        run_menu()
