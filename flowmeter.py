# flowmeter.py

import os
import sys
import time
import logging
import argparse
import random
import signal # Import signal for graceful termination
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import necessary components from their respective files and Scapy
from flow_generator import FlowGenerator
from constants import DEFAULT_PCAP_PATH, DEFAULT_OUT_PATH, ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS
from flow_feature import FlowFeature
from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6, TCP, UDP, Raw, sniff, get_if_list # Import sniff and get_if_list

# --- Simple PCAP Generation Function (Keep this for file mode or testing) ---
def generate_simple_test_pcap(output_dir, filename="simple_test_flow.pcap", num_packets=10):
    """
    Generates a simple test PCAP file with a single TCP flow.
    This is for demonstration of the pipeline; generating realistic traffic is complex.
    """
    filepath = os.path.join(output_dir, filename)
    packets = []

    # Define source and destination IP and ports
    src_ip = "192.168.1.100"
    dst_ip = "8.8.8.8"
    src_port = random.randint(1024, 65535)
    dst_port = 80 # HTTP example

    logger.info(f"Generating simple test PCAP: {filename}")

    for i in range(num_packets):
        # Create a simple Ethernet -> IP -> TCP packet
        ether_layer = Ether()
        ip_layer = IP(src=src_ip, dst=dst_ip)
        # Use empty string for flags when not SYN or ACK
        tcp_flags = "S" if i == 0 else ("A" if i == 1 else "")
        tcp_layer = TCP(sport=src_port, dport=dst_port, flags=tcp_flags, seq=i*100, ack=i*100 + 1) # Simulate some sequence/ack
        # Add a small payload
        payload = f"Packet {i}".encode()
        packet = ether_layer / ip_layer / tcp_layer / payload
        # Adjust timestamp (Scapy uses floating point seconds since epoch)
        packet.time = time.time() + i * 0.01 # Add a small delay between packets

        packets.append(packet)

    try:
        wrpcap(filepath, packets)
        logger.info(f"Generated {len(packets)} packets in {filepath}")
        return filepath # Return the path of the generated file
    except Exception as e:
        logger.error(f"Error generating PCAP file {filepath}: {e}")
        return None

# --- Packet Processing Function for Live Capture ---
# This function will be called by Scapy's sniff() for each captured packet
def process_live_packet(packet, flow_generator, output_dir):
    """
    Processes a single packet captured live and adds it to the flow generator.
    """
    # We don't need to pass the output_dir to flow_generator.addPacket
    # FlowGenerator will handle internal state updates.
    # Dumping to CSV will happen at the end of sniffing.
    try:
        flow_generator.addPacket(packet)
    except Exception as e:
         # Log any errors during packet processing but don't stop sniffing
         logger.error(f"Error processing live packet: {e}", exc_info=True)


# --- Main Function with Live Capture Mode ---
def main():
    parser = argparse.ArgumentParser(description="Python version of CICFlowMeter.")
    parser.add_argument("--pcap-path", default=DEFAULT_PCAP_PATH,
                        help=f"Path to directory containing .pcap files (default: {DEFAULT_PCAP_PATH})")
    parser.add_argument("--out-path", default=DEFAULT_OUT_PATH,
                        help=f"Path to output directory for .csv files (default: {DEFAULT_OUT_PATH})")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip generating the simple test PCAP (only applicable in file mode).")
    parser.add_argument("--interface", help="Network interface to sniff on for live capture.")
    parser.add_argument("--sniff-timeout", type=int, default=0,
                        help="Timeout for live sniffing in seconds (0 means indefinite).")
    parser.add_argument("--sniff-count", type=int, default=0,
                        help="Number of packets to sniff for live capture (0 means indefinite).")


    args = parser.parse_args()

    pcap_path = args.pcap_path
    out_path = args.out_path

    # Ensure output directory exists
    os.makedirs(out_path, exist_ok=True)

    # Initialize the FlowGenerator outside the processing loop
    flow_gen = FlowGenerator(bidirectional=True, flow_timeout_micros=ACTIVE_TIMEOUT_MICROS, activity_timeout_micros=IDLE_TIMEOUT_MICROS)

    if args.interface:
        # --- Live Capture Mode ---
        interface = args.interface
        logger.info(f"Starting live capture on interface: {interface}")
        logger.info(f"Sniffing timeout: {args.sniff_timeout}s, Packet count limit: {args.sniff_count}")
        logger.info("Press Ctrl+C to stop sniffing and dump flows.")

        # --- TEMPORARILY COMMENT OUT SIGNAL HANDLING SETUP ---
        # Define a handler for graceful termination
        # stop_sniffing = False
        # def stop_handler(signum, frame):
        #     global stop_sniffing
        #     stop_sniffing = True
        #     logger.info("Sniffing interrupted by user (Ctrl+C). Stopping capture...")
        #
        # # Register the signal handler for SIGINT (Ctrl+C)
        # signal.signal(signal.SIGINT, stop_handler)
        # --- END TEMPORARY COMMENT OUT ---


        # Initialize the FlowGenerator outside the processing loop
        flow_gen = FlowGenerator(bidirectional=True, flow_timeout_micros=ACTIVE_TIMEOUT_MICROS, activity_timeout_micros=IDLE_TIMEOUT_MICROS)
        logger.debug("FlowGenerator initialized...")


        try:
            # Define the packet callback for live capture
            def packet_callback_wrapper(packet):
                 # Reintroduce the call to process_live_packet
                 logger.debug("Packet callback invoked.") # Keep this debug line
                 # Keep the stop_sniffing check commented out
                 # if stop_sniffing:
                 #      logger.debug("Stop sniffing flag detected.")
                 #      raise StopIteration
                 process_live_packet(packet, flow_gen, out_path) # Keep processing call


            logger.debug("Calling scapy.sniff()...")
            # Start sniffing live traffic
            # Use original timeout/count args (0, 0 for indefinite sniff)
            sniff(iface=interface, prn=packet_callback_wrapper, store=0) # Use original args
            logger.debug("scapy.sniff() returned.")


        except StopIteration: # This block won't be reached with signal handling commented out
             logger.info("Sniffing stopped.")
        except Exception as e:
            # This will catch exceptions *during* sniff or if sniff raises on failure
            logger.error(f"An error occurred during live sniffing: {e}", exc_info=True)
            logger.info("Troubleshooting live capture:")
            logger.info("1. Ensure you have administrator or root privileges.")
            logger.info(f"2. Verify interface name. Available interfaces: {get_if_list()}")

        # Dumping logic after sniff returns
        logger.info("Sniffing stopped. Dumping remaining flows...")
        final_dump_timestamp = int(time.time() * 1_000_000) # Use current time for final close
        flow_gen.close_all_flows(final_dump_timestamp) # Close any remaining active flows

        # Determine output filename for live capture
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_interface_name = interface.replace('\\', '_').replace('{', '').replace('}', '').replace(':', '_').replace('*', '_').replace('?', '_').replace('"', '_').replace('<', '_').replace('>', '_').replace('|', '_').replace('/', '_') # Add more replacements if needed

        # Now use the sanitized name in the filename
        live_csv_filename = f"live_capture_{sanitized_interface_name}_{timestamp_str}_PythonFeatures.csv"

        total_flows_dumped = flow_gen.dump_labeled_flow_based_features(out_path, live_csv_filename, FlowFeature.get_header())
        logger.info(f"Dumped {total_flows_dumped} flows from live capture on {interface}.")


    else:
        # --- PCAP File Processing Mode (Existing Logic) ---

        # Pipeline Step 1: Generate PCAPs (simple test PCAP) - Only in file mode
        if not args.skip_generate:
            os.makedirs(pcap_path, exist_ok=True)
            generate_simple_test_pcap(pcap_path)
        else:
            logger.info("Skipping simple test PCAP generation as --skip-generate flag is set.")

        # Pipeline Step 2: Process PCAP files
        if not os.path.isdir(pcap_path):
            logger.error("Input directory not found: %s", pcap_path)
            sys.exit(1)

        try:
            pcap_files = [f for f in os.listdir(pcap_path) if f.lower().endswith(".pcap")]
            pcap_files.sort()
        except OSError as e:
            logger.error("Error listing files in directory %s: %s", pcap_path, e)
            sys.exit(1)

        if not pcap_files:
            logger.info("Sorry, no pcap files can be found under: %s", pcap_path)
            if args.skip_generate:
                 logger.info("Note: No PCAP files found and generation was skipped. Please ensure PCAP files are in the input directory or remove --skip-generate.")
            return

        logger.info("")
        logger.info("PythonFlowMeter found: %d Files.", len(pcap_files))

        total_flows_dumped = 0

        for file in pcap_files:
            filepath = os.path.join(pcap_path, file)
            logger.info("")
            logger.info("")
            logger.info("Working on... %s", file)

            # Re-initialize FlowGenerator for each file in file mode (matching Java's behavior)
            # This ensures flow IDs are unique per file processed in a single run.
            # If you wanted continuous flows across files, the flow_gen should be initialized once before the loop.
            # Sticking to per-file initialization for closer Java behavior translation.
            flow_gen = FlowGenerator(bidirectional=True, flow_timeout_micros=ACTIVE_TIMEOUT_MICROS, activity_timeout_micros=IDLE_TIMEOUT_MICROS)


            first_packet_timestamp_micros = None
            last_packet_timestamp_micros = None
            discarded_packet_count = 0

            start_time_script_sec = time.time()

            packets = []
            total_scapy_packets = 0

            try:
                try:
                    packets = rdpcap(filepath)
                    total_scapy_packets = len(packets)
                    logger.info(f"Read {total_scapy_packets} packets from {file}")
                except Exception as e:
                     logger.error(f"Error reading PCAP file {filepath}: {e}")
                     continue

                for i, packet in enumerate(packets):
                    try:
                        flow_gen.addPacket(packet)

                        if hasattr(packet, 'time'):
                            packet_timestamp_micros = int(packet.time * 1_000_000)
                            if first_packet_timestamp_micros is None or packet_timestamp_micros < first_packet_timestamp_micros:
                                 first_packet_timestamp_micros = packet_timestamp_micros
                            if last_packet_timestamp_micros is None or packet_timestamp_micros > last_packet_timestamp_micros:
                                 last_packet_timestamp_micros = packet_packet_timestamp_micros # Fix typo here (was packet_packet_timestamp_micros)
                            if last_packet_timestamp_micros is None or packet_timestamp_micros > last_packet_timestamp_micros:
                                last_packet_timestamp_micros = packet_timestamp_micros
                        else:
                             logger.warning(f"Packet {i+1} in {file} has no timestamp attribute. Skipping time tracking for this packet.")


                    except Exception as e:
                         logger.error(f"Unhandled error processing packet {i+1}/{total_scapy_packets} in PCAP loop: {e}", exc_info=True)
                         discarded_packet_count += 1

                final_closing_timestamp = last_packet_timestamp_micros if last_packet_timestamp_micros is not None else int(time.time() * 1_000_000)
                logger.debug(f"Calling close_all_flows for {file} with final timestamp {final_closing_timestamp}")
                flow_gen.close_all_flows(final_closing_timestamp)

            except Exception as e:
                logger.error(f"An unhandled error occurred during processing of file {file}: {e}", exc_info=True)


            end_time_script_sec = time.time()
            logger.info("Done! processing file %s in %.2f seconds", file, (end_time_script_sec - start_time_script_sec))
            logger.info("\t Total packets read by scapy: %d", total_scapy_packets)
            logger.info("\t Packets causing errors or filtered by addPacket: %d", discarded_packet_count)

            if first_packet_timestamp_micros is not None and last_packet_timestamp_micros is not None:
                 pcap_duration_micros = last_packet_timestamp_micros - first_packet_timestamp_micros
                 if pcap_duration_micros >= 0:
                      logger.info("PCAP duration %.6f seconds", pcap_duration_micros / 1_000_000.0)
                 else:
                      logger.warning("Calculated negative PCAP duration. Timestamps might be inconsistent.")
                      logger.info("PCAP duration: N/A")
            else:
                 logger.info("PCAP duration: N/A (no packets read or processed)")

            logger.info("----------------------------------------------------------------------------")

            csv_filename = file.replace(".pcap", "") + "_PythonFeatures.csv"
            total_flows_dumped_this_file = flow_gen.dump_labeled_flow_based_features(out_path, csv_filename, FlowFeature.get_header())
            total_flows_dumped += total_flows_dumped_this_file
            logger.info("Dumped %d flows for file %s.", total_flows_dumped_this_file, file)


        # In file mode, total_flows_dumped is accumulated across all files
        logger.info("\n\n----------------------------------------------------------------------------")
        logger.info("TOTAL FLOWS DUMPED ACROSS ALL FILES (packet count > 1): %d", total_flows_dumped)
        logger.info("----------------------------------------------------------------------------\n")


if __name__ == "__main__":
    main()