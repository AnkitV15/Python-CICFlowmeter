# flowmeter.py

import os
import sys
import time
import logging
import argparse

# Configure logging
# Set level to DEBUG to see detailed flow processing logs
# For production, you might change this to logging.INFO or higher
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Get logger for the main module

# Import necessary components from their respective files and Scapy
from flow_generator import FlowGenerator
from constants import DEFAULT_PCAP_PATH, DEFAULT_OUT_PATH, ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS
from flow_feature import FlowFeature # Needed for getting the header
from scapy.all import rdpcap # Import rdpcap here as it's used in main

def main():
    parser = argparse.ArgumentParser(description="Python version of CICFlowMeter.")
    parser.add_argument("pcap_path", nargs="?", default=DEFAULT_PCAP_PATH,
                        help=f"Path to directory containing .pcap files (default: {DEFAULT_PCAP_PATH})")
    parser.add_argument("out_path", nargs="?", default=DEFAULT_OUT_PATH,
                        help=f"Path to output directory for .csv files (default: {DEFAULT_OUT_PATH})")
    args = parser.parse_args()

    pcap_path = args.pcap_path
    out_path = args.out_path

    if not os.path.isdir(pcap_path):
        logger.error("Input directory not found: %s", pcap_path)
        sys.exit(1)

    # Find all .pcap files
    try:
        pcap_files = [f for f in os.listdir(pcap_path) if f.lower().endswith(".pcap")]
        pcap_files.sort() # Process files in a consistent order
    except OSError as e:
        logger.error("Error listing files in directory %s: %s", pcap_path, e)
        sys.exit(1)


    if not pcap_files:
        logger.info("Sorry, no pcap files can be found under: %s", pcap_path)
        return

    logger.info("")
    logger.info("PythonFlowMeter found: %d Files.", len(pcap_files))

    total_flows_dumped = 0 # Tracks the total number of flows successfully dumped across all files

    for file in pcap_files:
        filepath = os.path.join(pcap_path, file)
        logger.info("")
        logger.info("")
        logger.info("Working on... %s", file)

        # Create a new FlowGenerator for each file, matching Java's loop structure
        # Pass timeouts in microseconds to match BasicFlow and Java logic
        flow_gen = FlowGenerator(bidirectional=True, flow_timeout_micros=ACTIVE_TIMEOUT_MICROS, activity_timeout_micros=IDLE_TIMEOUT_MICROS)

        # Variables to track PCAP duration based on actual packet timestamps
        first_packet_timestamp_micros = None
        last_packet_timestamp_micros = None
        discarded_packet_count = 0 # Packets that caused errors or were filtered out in addPacket

        start_time_script_sec = time.time() # For script duration timing in seconds

        packets = [] # Initialize packets list for the current file
        total_scapy_packets = 0 # Initialize packet count for the current file

        try:
            # Use rdpcap to read packets from the file
            # rdpcap can raise exceptions (e.g., corrupted file)
            try:
                packets = rdpcap(filepath)
                total_scapy_packets = len(packets)
                logger.info(f"Read {total_scapy_packets} packets from {file}")
            except Exception as e:
                 logger.error(f"Error reading PCAP file {filepath}: {e}")
                 continue # Skip to the next file if reading fails


            # Iterate through packets and add to flow generator
            for i, packet in enumerate(packets):
                # The addPacket method handles internal filtering (non-IP/IPv6) and errors during BasicPacketInfo creation.
                # It also catches errors during adding to flows and new flow creation.
                # If addPacket returns or raises an exception here, it means the packet couldn't be processed for flows.
                try:
                    flow_gen.addPacket(packet)

                    # Track first/last timestamp of packets *read by scapy*
                    # This might include non-IP/IPv6 packets, mirroring the Java PacketReader's overall tracking
                    # Ensure packet has a time attribute before accessing
                    if hasattr(packet, 'time'):
                        packet_timestamp_micros = int(packet.time * 1_000_000)
                        if first_packet_timestamp_micros is None or packet_timestamp_micros < first_packet_timestamp_micros:
                             first_packet_timestamp_micros = packet_timestamp_micros
                        if last_packet_timestamp_micros is None or packet_timestamp_micros > last_packet_timestamp_micros:
                             last_packet_timestamp_micros = packet_timestamp_micros
                    else:
                         logger.warning(f"Packet {i+1} in {file} has no timestamp attribute. Skipping time tracking for this packet.")


                except Exception as e:
                     # This catch block is for unexpected errors that escape addPacket's internal handling
                     logger.error(f"Unhandled error processing packet {i+1}/{total_scapy_packets} in PCAP loop: {e}", exc_info=True) # Log traceback
                     discarded_packet_count += 1 # Count packets that couldn't be added for any reason


            # Close any remaining active flows at the end of the file
            # Use the timestamp of the last packet read by scapy if available, otherwise current time.
            final_closing_timestamp = last_packet_timestamp_micros if last_packet_timestamp_micros is not None else int(time.time() * 1_000_000)
            logger.debug(f"Calling close_all_flows for {file} with final timestamp {final_closing_timestamp}")
            flow_gen.close_all_flows(final_closing_timestamp)


        except Exception as e:
            # This catches any exceptions not caught in the inner loops
            logger.error(f"An unhandled error occurred during processing of file {file}: {e}", exc_info=True) # Log traceback
            # Continue to the next file if an unhandled error occurs


        end_time_script_sec = time.time()
        logger.info("Done! processing file %s in %.2f seconds", file, (end_time_script_sec - start_time_script_sec))
        logger.info("\t Total packets read by scapy: %d", total_scapy_packets)
        # Packets processed could be estimated by total - discarded, but it's an estimate.
        # The number of flows dumped is a more reliable metric of success.
        logger.info("\t Packets causing errors or filtered by addPacket: %d", discarded_packet_count)


        if first_packet_timestamp_micros is not None and last_packet_timestamp_micros is not None:
             # Convert microseconds duration to seconds for logging
             pcap_duration_micros = last_packet_timestamp_micros - first_packet_timestamp_micros
             # Prevent negative duration if only one packet or timestamps are odd
             if pcap_duration_micros >= 0:
                  logger.info("PCAP duration %.6f seconds", pcap_duration_micros / 1_000_000.0)
             else:
                  logger.warning("Calculated negative PCAP duration. Timestamps might be inconsistent.")
                  logger.info("PCAP duration: N/A")

        else:
             logger.info("PCAP duration: N/A (no packets read or processed)")

        logger.info("----------------------------------------------------------------------------")

        # Dump flows to CSV
        csv_filename = file.replace(".pcap", "") + "_PythonFeatures.csv" # Naming convention
        total_flows_dumped_this_file = flow_gen.dump_labeled_flow_based_features(out_path, csv_filename, FlowFeature.get_header())
        total_flows_dumped += total_flows_dumped_this_file
        logger.info("Dumped %d flows for file %s.", total_flows_dumped_this_file, file)


    logger.info("\n\n----------------------------------------------------------------------------")
    # The Java code reports total flows from finishedFlows + currentFlows *before* dumping.
    # This Python version reports the total number of flows actually dumped to CSV (packet count > 1).
    logger.info("TOTAL FLOWS DUMPED ACROSS ALL FILES (packet count > 1): %d", total_flows_dumped)
    logger.info("----------------------------------------------------------------------------\n")

if __name__ == "__main__":
    main()