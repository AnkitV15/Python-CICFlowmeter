# flowmeter.py

import os
import sys
import time
import logging
import argparse
import random # Needed for simple packet generation

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') # Set to INFO for less verbose output
logger = logging.getLogger(__name__)

# Import necessary components from their respective files and Scapy
from flow_generator import FlowGenerator
from constants import DEFAULT_PCAP_PATH, DEFAULT_OUT_PATH, ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS
from flow_feature import FlowFeature
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP # Import wrpcap for writing pcaps

# --- Simple PCAP Generation Function ---
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


def main():
    parser = argparse.ArgumentParser(description="Python version of CICFlowMeter.")
    parser.add_argument("pcap_path", nargs="?", default=DEFAULT_PCAP_PATH,
                        help=f"Path to directory containing .pcap files (default: {DEFAULT_PCAP_PATH})")
    parser.add_argument("out_path", nargs="?", default=DEFAULT_OUT_PATH,
                        help=f"Path to output directory for .csv files (default: {DEFAULT_OUT_PATH})")
    # Optional argument to skip built-in PCAP generation
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip generating the simple test PCAP.")

    args = parser.parse_args()

    pcap_path = args.pcap_path
    out_path = args.out_path

    # Ensure output directory exists
    os.makedirs(out_path, exist_ok=True)

    # --- Pipeline Step 1: Generate PCAPs (simple test PCAP) ---
    if not args.skip_generate:
        # Ensure input directory exists to save the generated PCAP
        os.makedirs(pcap_path, exist_ok=True)
        generate_simple_test_pcap(pcap_path)
    else:
        logger.info("Skipping simple test PCAP generation as --skip-generate flag is set.")


    # --- Pipeline Step 2: Process PCAP files ---
    if not os.path.isdir(pcap_path):
        logger.error("Input directory not found: %s", pcap_path)
        sys.exit(1)

    # Find all .pcap files (including the potentially newly generated one)
    try:
        pcap_files = [f for f in os.listdir(pcap_path) if f.lower().endswith(".pcap")]
        pcap_files.sort() # Process files in a consistent order
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

        flow_gen = FlowGenerator(bidirectional=True, flow_timeout_micros=ACTIVE_TIMEOUT_MICROS, activity_timeout_micros=IDLE_TIMEOUT_MICROS)

        first_packet_timestamp_micros = None
        last_packet_timestamp_micros = None
        discarded_packet_count = 0

        start_time_script_sec = time.time()

        packets = []
        total_scapy_packets = 0

        try:
            try:
                # Use rdpcap to read packets from the file
                packets = rdpcap(filepath)
                total_scapy_packets = len(packets)
                logger.info(f"Read {total_scapy_packets} packets from {file}")
            except Exception as e:
                 logger.error(f"Error reading PCAP file {filepath}: {e}")
                 continue # Skip to the next file if reading fails

            for i, packet in enumerate(packets):
                try:
                    flow_gen.addPacket(packet)

                    if hasattr(packet, 'time'):
                        packet_timestamp_micros = int(packet.time * 1_000_000)
                        if first_packet_timestamp_micros is None or packet_timestamp_micros < first_packet_timestamp_micros:
                             first_packet_timestamp_micros = packet_timestamp_micros
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


    logger.info("\n\n----------------------------------------------------------------------------")
    logger.info("TOTAL FLOWS DUMPED ACROSS ALL FILES (packet count > 1): %d", total_flows_dumped)
    logger.info("----------------------------------------------------------------------------\n")

if __name__ == "__main__":
    main()