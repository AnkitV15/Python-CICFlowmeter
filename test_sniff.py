from scapy.all import sniff, get_if_list
import sys

# interface_name = input("Enter interface name (e.g., \\Device\\NPF_{...}): ") manually enter interface in terminal

interface_name = r"\Device\NPF_{6D4B8695-9F95-43E3-9080-DCF2C65A0FF8}"

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1
    print(f"Captured packet {packet_count}: {packet.summary()}")
    if packet_count >= 5: # Stop after capturing 5 packets for a quick test
        sys.exit(0) # Exit gracefully

print(f"Starting simple sniff on {interface_name}. Capture up to 5 packets.")
print("Press Ctrl+C to stop.")

try:
    # Sniff indefinitely until 5 packets are captured or Ctrl+C is pressed
    # store=0 prevents storing packets in memory
    sniff(iface=interface_name, prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nSniffing interrupted by user.")
except Exception as e:
    print(f"\nAn error occurred during sniffing: {e}")

print(f"Finished sniffing. Captured {packet_count} packets.")