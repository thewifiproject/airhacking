import logging
import os
import hmac
import hashlib
import platform
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import *
from typing import Tuple

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Constants for TLS key derivation (simplified example)
TLS_MASTER_SECRET_LABEL = b"master secret"

def extract_session_keys(packet: Packet) -> Tuple[bytes, bytes]:
    # Check if this is a TLS handshake packet (assuming it's a TLS handshake message)
    if b'\x16\x03' not in packet:
        return b"", b""

    # Extract the client hello message
    client_hello = packet.getlayer(TLSClientHello)

    # If no client hello message, return empty bytes for pre-master secret and session ID
    if client_hello is None:
        return b"", b""

    # Extract the random value from the client hello message
    random_value = client_hello.random

    # Calculate the pre-master secret using the TLS PRF (simplified)
    hmac_sha256 = hmac.new(random_value, TLS_MASTER_SECRET_LABEL + bytes(16), hashlib.sha256)
    pre_master_secret = hmac_sha256.digest()

    # Extract the session ID from the client hello message
    session_id = client_hello.session_id

    return pre_master_secret, session_id

def derive_master_secret(pre_master_secret: bytes) -> bytes:
    # Simplified version of the TLS PRF (this is not a full implementation)
    hmac_sha256 = hmac.new(pre_master_secret, TLS_MASTER_SECRET_LABEL + b"session_id", hashlib.sha256)
    master_secret = hmac_sha256.digest()
    return master_secret

def decrypt_packet(packet: bytes) -> Tuple[str, str]:
    try:
        if len(packet) < 16:  # Some packets may be too short to contain a valid TLS packet
            return "Packet decrypted", " "

        # Extract pre-master secret and session ID
        pre_master_secret, session_id = extract_session_keys(packet)
        if not pre_master_secret or not session_id:
            return "Packet decrypted", " "

        # Derive the AES key (using the first 16 bytes of the pre-master secret for AES-128)
        key = pre_master_secret[:16]  # For AES-128, we use the first 16 bytes of the pre-master secret
        iv_size = len(session_id)
        session_id_padded = session_id.ljust(16, b'\x00')  # Add padding to IV until it reaches 16 bytes

        # Create the AES CBC cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(session_id_padded), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the packet (skip the first 16 bytes, assuming it's the header)
        decrypted_data = decryptor.update(packet[16:]) + decryptor.finalize()

        return "Packet successfully decrypted", decrypted_data.decode(errors='replace')

    except Exception as e:
        logger.error(f"Error decrypting packet: {e}")
        return "Failed to decrypt packet", str(e)

def packet_callback(packet):
    try:
        if packet.haslayer(Raw):  # Check if the packet has a Raw layer
            decrypted_packet = decrypt_packet(packet[Raw].load)
            logger.info(f"Packet Hash: {packet[Raw].load.hex()} | Decrypted Text: {decrypted_packet[1]}")
            print(f"Decrypted Packet: {decrypted_packet[1]}")  # Print decrypted data
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def sniff_traffic(interface: str) -> None:
    logger.info(f"Starting packet sniffing on interface {interface}...")
    try:
        # Sniff the network and process the packets in real-time
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        logger.info("\nSniffing stopped by user.")
    except Exception as e:
        logger.error(f"Error during sniffing: {e}")

def get_network_interface() -> str:
    """
    Detects the network interface on the current platform (Linux/Windows)
    and returns the interface name.
    """
    try:
        if platform.system() == 'Windows':
            # On Windows, we will use Scapy's get_if_list() to detect interfaces
            interfaces = get_if_list()
            logger.info(f"Available interfaces: {interfaces}")
            # You can adjust this if necessary to pick a specific interface
            return interfaces[1]  # This will return the second available interface (e.g., Wi-Fi or Ethernet)
        else:
            # On Linux, we will also use get_if_list() but specify the interface as needed
            interfaces = get_if_list()
            logger.info(f"Available interfaces: {interfaces}")
            return interfaces[0]  # You can modify to pick a specific interface like eth0 or wlan0
    except Exception as e:
        logger.error(f"Error detecting network interfaces: {e}")
        raise

if __name__ == "__main__":
    try:
        interface = get_network_interface()  # Dynamically detect interface
        sniff_traffic(interface)

    except Exception as e:
        logger.error(f"An error occurred during execution: {str(e)}")
