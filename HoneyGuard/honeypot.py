"""
HoneyGuard SSH Honeypot Engine
Powered by Paramiko. Simulates a legitimate Linux SSH service, logs every authentication attempt,
evaluates real-time intrusion rules, and GUARANTEES that attackers are never granted a shell.
"""

import socket
import threading
import logging
from typing import Optional, Callable, Dict, Any
import paramiko
import config
import db
import rules

logger = logging.getLogger("HoneyGuard.SSH")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def get_or_create_host_key() -> paramiko.RSAKey:
    """Loads or automatically generates a persistent RSA host key for the SSH server."""
    key_path = config.HOST_KEY_PATH
    if key_path.exists():
        try:
            return paramiko.RSAKey(filename=str(key_path))
        except Exception as e:
            logger.warning(f"Could not load existing key ({e}). Generating new host key...")

    logger.info("Generating new 2048-bit RSA host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key

def resolve_geoip(ip: str) -> Dict[str, Any]:
    """
    Offline/Fast GeoIP resolver. Returns coordinates and country metadata.
    Avoids external API bottlenecks during brute force floods.
    """
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return {
            "country": "Localhost / Internal Test",
            "city": "Test Lab",
            "lat": 28.6139,
            "lon": 77.2090
        }

    # Built-in lightweight offline lookup for common test ranges / public IPs
    sample_geo = {
        "185.220.": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
        "194.26.": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
        "45.33.": {"country": "United States", "city": "Fremont", "lat": 37.5485, "lon": -121.9886},
        "103.251.": {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
        "218.92.": {"country": "China", "city": "Jiangsu", "lat": 32.0617, "lon": 118.7632},
        "91.240.": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173}
    }
    for prefix, info in sample_geo.items():
        if ip.startswith(prefix):
            return info

    # Default fallback coordinates (Atlantic Ocean / Global Attacker)
    return {
        "country": "External Origin",
        "city": "Internet Node",
        "lat": 20.0,
        "lon": 0.0
    }

class HoneyGuardSSHInterface(paramiko.ServerInterface):
    """
    Custom Paramiko SSH server implementation.
    Enforces absolute denial of shells and commands while capturing credentials.
    """
    def __init__(self, client_ip: str, client_port: int, on_event_callback: Optional[Callable] = None):
        super().__init__()
        self.client_ip = client_ip
        self.client_port = client_port
        self.callback = on_event_callback
        self.client_version = "Unknown"

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Intercepts login credentials.
        ALWAYS returns AUTH_FAILED to prevent any unauthorized server penetration.
        """
        logger.warning(f"[ATTACK DETECTED] From {self.client_ip}:{self.client_port} -> User: '{username}' | Password: '{password}'")

        # 1. Resolve GeoIP
        geo = resolve_geoip(self.client_ip)

        # 2. Log attempt to SQLite
        attack_id = db.log_attack(
            ip=self.client_ip,
            port=self.client_port,
            username=username,
            password=password,
            client_version=self.client_version,
            geo=geo
        )

        # 3. Evaluate real-time intrusion rules (Brute Force / Credential Stuffing)
        triggered_rules = rules.evaluate_login(self.client_ip, username, password)

        # 4. Notify live dashboard via WebSocket callback
        if self.callback:
            try:
                event_data = {
                    "id": attack_id,
                    "ip": self.client_ip,
                    "port": self.client_port,
                    "username": username,
                    "password": password,
                    "country": geo.get("country", "Unknown"),
                    "city": geo.get("city", "Unknown"),
                    "lat": geo.get("lat", 0.0),
                    "lon": geo.get("lon", 0.0),
                    "triggered_rules": triggered_rules
                }
                self.callback(event_data)
            except Exception as e:
                logger.error(f"Error executing dashboard event callback: {e}")

        # ALWAYS REJECT LOGIN! Decoy never authorizes an attacker
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """Advises client that password authentication is supported."""
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """CRITICAL SECURITY: Always refuse any session or channel open request."""
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        """CRITICAL SECURITY: Refuse command execution."""
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        """CRITICAL SECURITY: Refuse interactive pseudo-terminal allocation."""
        return False

    def check_channel_shell_request(self, channel) -> bool:
        """CRITICAL SECURITY: Refuse shell spawning."""
        return False

class HoneypotServer:
    """Multi-threaded SSH Honeypot Listener."""
    def __init__(self, host: str = config.HONEYPOT_HOST, port: int = config.HONEYPOT_PORT,
                 on_event_callback: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.callback = on_event_callback
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.host_key = get_or_create_host_key()

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        client_ip, client_port = addr
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = config.SSH_BANNER
            transport.add_server_key(self.host_key)

            ssh_interface = HoneyGuardSSHInterface(client_ip, client_port, self.callback)
            
            # Start SSH negotiation
            transport.start_server(server=ssh_interface)
            ssh_interface.client_version = transport.remote_version or "Unknown"

            # Wait briefly for auth exchanges
            transport.join(timeout=15)

        except (paramiko.SSHException, socket.error, ConnectionResetError, ConnectionAbortedError):
            # Normal network disconnects or port probes before SSH negotiation
            pass
        except Exception as exc:
            logger.debug(f"Connection closed for {client_ip}:{client_port} ({exc})")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

    def start(self):
        """Starts the honeypot listener."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.running = True

        logger.info(f"🍯 HoneyGuard Decoy SSH Server listening on {self.host}:{self.port}")

        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                client_ip = addr[0]

                # Check Port Scan rule on raw connection
                scan_alert = rules.record_raw_connection(client_ip)
                if scan_alert and self.callback:
                    try:
                        self.callback({"scan_alert": scan_alert})
                    except Exception:
                        pass

                # Dispatch client to worker thread
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()

            except Exception as e:
                if self.running:
                    logger.error(f"Error in Honeypot accept loop: {e}")
                break

    def stop(self):
        """Stops the honeypot listener."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info("HoneyGuard Decoy SSH Server stopped.")

def run_standalone_honeypot():
    """Entry point for standalone honeypot execution."""
    db.init_db()
    server = HoneypotServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    run_standalone_honeypot()
