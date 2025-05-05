# isolated_sniff_test.py

import sys
import logging
import argparse
# Only import the absolute minimum needed for sniffing
from scapy.all import sniff, get_if_list

# Configure basic logging (ensure DEBUG is on)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Isolated Scapy Sniff Test.")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on.")
    # Add a small timeout so it doesn't run indefinitely if Ctrl+C doesn't work
    parser.add_argument("--sniff-timeout", type=int, default=10,
                        help="Timeout for live sniffing in seconds.")

    args = parser.parse_args()

    interface = args.interface

    logger.info(f"Starting isolated sniff test on interface: {interface}")
    logger.info(f"Sniffing timeout: {args.sniff_timeout}s")

    try:
        # Define a *very* basic packet callback that just logs
        def simple_callback(packet):
             logger.debug("Packet callback invoked. (Isolated test)")
             pass # Do nothing else

        logger.debug("Calling scapy.sniff()...")
        # Start sniffing live traffic with a timeout
        # store=0 prevents storing packets in memory
        sniff(iface=interface, prn=simple_callback, timeout=args.sniff_timeout, store=0)
        logger.debug("scapy.sniff() returned.")

    except Exception as e:
        logger.error(f"An error occurred during isolated sniffing: {e}", exc_info=True)
        logger.info("Troubleshooting live capture:")
        logger.info("1. Ensure you have administrator or root privileges.")
        logger.info(f"2. Verify interface name. Available interfaces: {get_if_list()}")

    logger.info("Isolated sniff test finished.")

if __name__ == "__main__":
    main()