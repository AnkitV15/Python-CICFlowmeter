# live_sniff_test_with_timeout.py

import sys
import logging
import argparse
import time # Import time to show start/end time
from scapy.all import sniff, get_if_list, Packet # Import Packet type hint

# Configure logging to show DEBUG messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def packet_callback(packet: Packet):
    """
    Simple callback function to process each captured packet.
    Logs a debug message when invoked.
    """
    # You could add more packet inspection here if needed,
    # but keeping it minimal for this test.
    logger.debug(f"[{time.time():.6f}] Packet callback invoked. Timestamp: {getattr(packet, 'time', 'N/A')}")
    # Optional: print a summary of the packet
    # print(f"Captured: {packet.summary()}")


def main():
    parser = argparse.ArgumentParser(description="Dedicated Scapy Live Sniff Test with Timeout.")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on.")
    parser.add_argument("--sniff-duration", type=int, default=10,
                        help="Duration for live sniffing in seconds (default: 10).")

    args = parser.parse_args()

    interface = args.interface
    sniff_duration = args.sniff_duration

    logger.info(f"Starting live sniff test on interface: {interface}")
    logger.info(f"Sniffing duration: {sniff_duration} seconds")
    logger.info("Generating network traffic during the sniff is recommended.")

    try:
        logger.debug("Calling scapy.sniff()...")
        start_time = time.time()

        # Start sniffing live traffic for the specified duration
        # prn=packet_callback: Calls our function for each packet
        # timeout=sniff_duration: Stops sniffing after this many seconds
        # store=0: Prevents storing packets in memory (important for long sniffs)
        sniff(iface=interface, prn=packet_callback, timeout=sniff_duration, store=0)

        end_time = time.time()
        logger.debug("scapy.sniff() returned.")
        logger.info(f"Sniffing completed after {end_time - start_time:.2f} seconds.")


    except Exception as e:
        # This will catch exceptions during the sniff call itself
        logger.error(f"An error occurred during live sniffing: {e}", exc_info=True)
        logger.info("Troubleshooting live capture:")
        logger.info("1. Ensure you have administrator or root privileges.")
        logger.info(f"2. Verify interface name. Available interfaces: {get_if_list()}")

    logger.info("Live sniff test finished.")

if __name__ == "__main__":
    main()
# Example command to run (replace the GUID with your working interface)
# Remember to run this command from an administrator terminal
# python live_sniff_test_with_timeout.py --interface "\Device\NPF_{6D4B8695-9F95-43E3-9080-DCF2C65A0FF8}"
