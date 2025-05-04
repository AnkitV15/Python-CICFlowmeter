# flow_generator.py

import csv
import time
import os
import logging
from typing import Dict # Used for type hinting

# Import necessary components from other files
from scapy.packet import Packet # Keep Packet import for type hinting
from packet_info import BasicPacketInfo
from basic_flow import BasicFlow
from flow_feature import FlowFeature # Needed for header dumping
from constants import ACTIVE_TIMEOUT_MICROS, IDLE_TIMEOUT_MICROS # Import timeouts

logger = logging.getLogger(__name__) # Get logger for this module

# --- Flow Generator Logic (based on FlowGenerator.java) ---
class FlowGenerator:
    def __init__(self, bidirectional: bool, flow_timeout_micros: int = ACTIVE_TIMEOUT_MICROS, activity_timeout_micros: int = IDLE_TIMEOUT_MICROS):
        self.bidirectional = bidirectional
        self.flow_timeout_micros = flow_timeout_micros
        self.activity_timeout_micros = activity_timeout_micros
        self.current_flows: Dict[str, BasicFlow] = {}  # Dictionary to store active flows: flow_id -> BasicFlow object
        self.finished_flows: list[BasicFlow] = [] # List to store completed flows
        self.finished_flow_count = 0 # To mimic the Java counter
        logger.debug("FlowGenerator initialized with flow_timeout=%d, activity_timeout=%d", flow_timeout_micros, activity_timeout_micros)


    def addPacket(self, packet: Packet):
        # Create BasicPacketInfo first, filtering non-IP/IPv6 packets
        packet_info = None
        try:
            packet_info = BasicPacketInfo(packet)
        except ValueError:
             # logger.debug("Skipping non-IP/IPv6 packet") # Too noisy for normal operation
             return # Skip this packet if it's not IP/IPv6
        except Exception as e:
             logger.error(f"Error creating BasicPacketInfo for packet from scapy: {e}")
             return # Skip this packet if BasicPacketInfo creation failed

        current_timestamp = packet_info.getTimeStamp()
        logger.debug(f"Processing packet id {packet_info.id}, timestamp {current_timestamp}")


        # Check for expired flows (active timeout) before processing the new packet
        # Make a copy of keys to avoid modifying the dict during iteration
        keys_to_check = list(self.current_flows.keys())
        # logger.debug(f"Checking {len(keys_to_check)} current flows for timeouts.") # Too noisy
        for flow_id in keys_to_check:
            flow = self.current_flows[flow_id] # Access directly after getting keys
            # Active Timeout: time since the *start* of the flow exceeds the flow timeout
            if (current_timestamp - flow.getFlowStartTime()) > self.flow_timeout_micros:
                 logger.debug(f"Flow {flow_id} timed out.")
                 # Pass the timestamp that caused the timeout for finalization
                 self._close_flow(flow_id, current_timestamp, "Active Timeout")


        # Determine potential flow IDs for the current packet
        fwd_id = packet_info.fwdFlowId()
        bwd_id = packet_info.bwdFlowId()
        logger.debug(f"Packet {packet_info.id} has fwd_id: {fwd_id}, bwd_id: {bwd_id}")


        # Check if the packet belongs to an existing flow
        flow_id = None
        if fwd_id in self.current_flows:
            flow_id = fwd_id
            logger.debug(f"Packet {packet_info.id} belongs to existing flow {flow_id} (via fwd_id).")
        elif bwd_id in self.current_flows:
            flow_id = bwd_id
            logger.debug(f"Packet {packet_info.id} belongs to existing flow {flow_id} (via bwd_id).")

        if flow_id is not None:
            # Packet belongs to an existing current flow
            flow = self.current_flows.get(flow_id) # Use .get() for safer retrieval, though key should exist


            if flow is None:
                 # This case should ideally not happen if flow_id was found in keys_to_check or dictionary lookups,
                 # but including a check as a safeguard against unexpected state.
                 logger.error(f"Flow {flow_id} unexpectedly not found in current_flows after lookup for packet {packet_info.id}! Skipping packet.")
                 return # Skip processing this packet

            logger.debug(f"Adding packet {packet_info.id} to existing flow {flow_id} (object id: {id(flow)}).")

            # Check for FIN or RST flags for flow termination (TCP only)
            if packet_info.getProtocol() == 6: # TCP
                terminate_flow = False
                if packet_info.hasFlagRST():
                    logger.debug(f"Packet {packet_info.id} has RST flag. Terminating flow {flow_id}.")
                    terminate_flow = True
                elif packet_info.hasFlagFIN():
                     # Logic for FIN flags involves counting FINs in both directions
                     # Increment directional FIN counts using the methods in BasicFlow
                     # Ensure flow.getSrc() is valid before calling isForwardPacket
                     if flow.getSrc() is not None:
                         is_forward = packet_info.isForwardPacket(flow.getSrc())
                         if is_forward:
                              flow.setFwdFINFlags()
                              logger.debug(f"Packet {packet_info.id} is FWD FIN. Flow {flow_id} FWD FIN count: {flow.getFwdFINFlags()}")
                         else:
                              flow.setBwdFINFlags()
                              logger.debug(f"Packet {packet_info.id} is BWD FIN. Flow {flow_id} BWD FIN count: {flow.getBwdFINFlags()}")
                     else:
                          logger.warning(f"Flow {flow_id} has None src IP when checking FIN flags for packet {packet_info.id}. Cannot determine direction.")


                     # Terminate if the sum of fwd_fin_flags and bwd_fin_flags is >= 2
                     if (flow.getFwdFINFlags() + flow.getBwdFINFlags()) >= 2:
                         logger.debug(f"Flow {flow_id} has >= 2 FIN flags. Terminating flow.")
                         terminate_flow = True


                if terminate_flow:
                     # Add the current packet before closing (Java behavior)
                     try:
                          flow.addPacket(packet_info)
                          logger.debug(f"Added terminating packet {packet_info.id} to flow {flow_id} before closing.")
                     except Exception as e:
                          logger.error(f"Error adding terminating packet {packet_info.id} to flow {flow_id}: {e}", exc_info=True) # Log traceback
                          # Still attempt to close the flow even if adding the last packet failed
                     self._close_flow(flow_id, current_timestamp, "FIN/RST Flag")
                     return # Flow closed, processing for this packet is done


            # If not terminated by timeouts, FIN, or RST, add the packet to the existing flow
            try:
                 flow.addPacket(packet_info)
                 logger.debug(f"Successfully added packet {packet_info.id} to existing flow {flow_id}.")
                 # self.current_flows[flow_id] = flow # Ensure the updated flow is in the map (redundant but harmless)
            except Exception as e:
                 logger.error(f"Error adding packet {packet_info.id} to existing flow {flow_id} (object id: {id(flow)}): {e}", exc_info=True) # Log traceback
                 # Do not remove the flow on error, might recover or be closed by timeout later.
                 # Consider incrementing a flow-specific error counter if needed.


        else:
            # New flow detected
            logger.debug(f"Packet {packet_info.id} is starting a new flow.")
            # Create a new BasicFlow instance
            new_flow = None # Initialize to None
            try:
                 # Use the constructor that takes the first packet.
                 # This constructor is now responsible for setting the flow's identity.
                 # No need to pass flowSrc, flowDst etc. here for NEW flows.
                 new_flow = BasicFlow(self.bidirectional, packet_info, activityTimeout=self.activity_timeout_micros)

                 # Add the new flow to the dictionary using its determined flowId
                 flow_id_for_dict = new_flow.getFlowId()

                 # Safeguard: Should not exist if this path is truly for new flows
                 if flow_id_for_dict in self.current_flows:
                      logger.warning(f"New flow creation for packet {packet_info.id} attempted to overwrite existing flow key {flow_id_for_dict}. This suggests a logic error in flow ID generation or timeout handling.")
                      # Decide how to handle: keep old flow? Overwrite? For now, overwrite like the Java map behavior.

                 self.current_flows[flow_id_for_dict] = new_flow
                 logger.debug(f"Created new flow {flow_id_for_dict} (object id: {id(new_flow)}) for packet {packet_info.id}. Added to current_flows.")

            except Exception as e:
                 # This catch block seems to be where the 'checkFlags' error during firstPacket is reported
                 logger.error(f"Error creating new flow for packet {packet_info.id}: {e}", exc_info=True) # Log traceback
                 # The error traceback clearly shows this is happening during the BasicFlow() constructor call,
                 # specifically inside firstPacket() -> checkFlags().
                 # If new flow creation failed, the flow object might be incomplete or not added to current_flows.
                 # The packet is discarded in terms of flow processing.


    def _close_flow(self, flow_id: str, current_timestamp: int, reason: str):
        """Helper method to finalize and move a flow."""
        flow = self.current_flows.pop(flow_id, None)
        if flow:
            logger.debug(f"Closing flow {flow_id} (object id: {id(flow)}). Reason: {reason}")
            # The Java code checks packetCount() > 1 before adding to finishedFlows.
            # This means flows with only one packet are discarded.
            if flow.packetCount() > 1:
                logger.debug(f"Flow {flow_id} has {flow.packetCount()} packets (> 1). Finalizing.")
                try:
                    # Finalize active/idle times with the timestamp that caused the close
                    flow.endActiveIdleTime(current_timestamp, self.activity_timeout_micros, self.flow_timeout_micros, reason in ["FIN/RST Flag"])
                    self.finished_flow_count += 1
                    self.finished_flows.append(flow)
                    logger.debug(f"Flow {flow_id} finalized and added to finished_flows. Total finished: {len(self.finished_flows)}")

                except Exception as e:
                     logger.error(f"Error finalizing flow {flow_id} (object id: {id(flow)}) before closing: {e}", exc_info=True) # Log traceback
                     # Still add the flow to finished_flows even if finalization failed, to potentially dump partial features
                     self.finished_flow_count += 1
                     self.finished_flows.append(flow)
                     logger.warning(f"Flow {flow_id} added to finished_flows despite finalization error.")


            else:
                logger.debug(f"Discarded flow {flow_id} (object id: {id(flow)}) with only {flow.packetCount()} packet(s). Reason: {reason}")
                pass # Discard flows with 1 packet
        else:
             logger.debug(f"Attempted to close flow {flow_id} but it was not found in current_flows.")


    def close_all_flows(self, current_timestamp: int):
        """Closes all remaining active flows at the end of processing."""
        keys_to_close = list(self.current_flows.keys())
        logger.debug(f"Closing all remaining {len(keys_to_close)} flows at end of PCAP processing.")
        for flow_id in keys_to_close:
             # Use the flow's last packet time for finalization if available, otherwise use the provided current_timestamp
             flow = self.current_flows.get(flow_id)
             if flow:
                 final_timestamp = flow.flowLastSeen if flow.flowLastSeen > 0 else current_timestamp
                 self._close_flow(flow_id, final_timestamp, "End of PCAP")
             else:
                 logger.warning(f"Flow {flow_id} was expected in current_flows during close_all_flows but not found.")


    def dump_labeled_flow_based_features(self, output_path: str, filename: str, header: str) -> int:
        """
        Writes completed and current flow features (with packet count > 1) to a CSV file.
        """
        total_dumped = 0

        output_filepath = os.path.join(output_path, filename)
        os.makedirs(output_path, exist_ok=True) # Create output directory if it doesn't exist

        try:
            with open(output_filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(header.split(',')) # Write header row
                logger.info(f"Writing features to {output_filepath}")

                # Dump finished flows (already filtered for packetCount() > 1 in _close_flow)
                logger.debug(f"Dumping {len(self.finished_flows)} finished flows.")
                for flow in self.finished_flows:
                    if flow is None:
                         logger.warning("Encountered None flow in finished_flows list.")
                         continue
                    try:
                         writer.writerow(flow.dumpFlowBasedFeaturesEx().split(','))
                         total_dumped += 1
                    except Exception as e:
                         logger.error(f"Error dumping finished flow {getattr(flow, 'flowId', 'UnknownID')} (object id: {id(flow)}) to CSV: {e}", exc_info=True) # Log traceback

                # Dump remaining current flows (those not terminated by timeouts or flags during processing)
                # These flows also need to have packetCount() > 1 to be dumped.
                # Their features are finalized when dumpFlowBasedFeaturesEx is called.
                # Filter out None values defensively
                current_flows_to_dump = [flow for flow in self.current_flows.values() if flow and flow.packetCount() > 1]
                logger.debug(f"Dumping {len(current_flows_to_dump)} remaining current flows with packet count > 1.")

                for flow in current_flows_to_dump:
                    # Flow should not be None due to list comprehension filter, but defensive check
                    if flow is None:
                         logger.warning("Encountered None flow in current_flows values during dump.")
                         continue
                    try:
                         # Finalize features for current flows before dumping
                         # Use the flow's last packet time for finalization
                         final_timestamp = flow.flowLastSeen if flow.flowLastSeen > 0 else int(time.time() * 1_000_000)
                         # Use flow_timeout_micros for endActiveIdleTime when not flag terminated
                         flow.endActiveIdleTime(final_timestamp, self.activity_timeout_micros, self.flow_timeout_micros, False) # Not ended by flag
                         writer.writerow(flow.dumpFlowBasedFeaturesEx().split(','))
                         total_dumped += 1
                    except Exception as e:
                         logger.error(f"Error dumping current flow {getattr(flow, 'flowId', 'UnknownID')} (object id: {id(flow)}) to CSV: {e}", exc_info=True) # Log traceback


            logger.info("Successfully dumped %d flows to %s", total_dumped, output_filepath)
            return total_dumped
        except IOError as e:
            logger.error("Error writing to CSV file %s: %s", output_filepath, e)
            return 0
        except Exception as e:
             logger.error(f"An unexpected error occurred during CSV dumping: {e}", exc_info=True)
             return 0