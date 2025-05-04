import os
import sys
import time
import logging
import argparse
import enum
import socket
import struct
import statistics
from datetime import datetime

# Configure logging
# Set level to DEBUG to see detailed flow processing logs
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# Reduce logging noise for less critical debug messages if needed later
# logging.getLogger('__main__').setLevel(logging.INFO)


logger = logging.getLogger(__name__)


# Define default paths
DEFAULT_PCAP_PATH = os.path.join(os.getcwd(), "data", "in")
DEFAULT_OUT_PATH = os.path.join(os.getcwd(), "data", "out")

# Define flow timeouts in microseconds (matching Java's internal representation)
ACTIVE_TIMEOUT_MICROS = 120_000_000
IDLE_TIMEOUT_MICROS = 5_000_000

# --- Flow Feature Enum (based on FlowFeature.java) ---
class FlowFeature(enum.Enum):
    # Full list of 85 features as per FlowFeature.java
    # The order here defines the output column order
    fid = ("Flow ID", "FID", False)
    src_ip = ("Src IP", "SIP", False)
    src_port = ("Src Port", "SPT", True)
    dst_ip = ("Dst IP", "DIP", False)
    dst_pot = ("Dst Port", "DPT", True)
    prot = ("Protocol", "PROT", True)
    tstp = ("Timestamp", "TSTP", False)
    fl_dur = ("Flow Duration", "DUR", True)
    tot_fw_pkt = ("Total Fwd Packet", "TFwP", True)
    tot_bw_pkt = ("Total Bwd packets", "TBwP", True)
    tot_l_fw_pkt = ("Total Length of Fwd Packet", "TLFwP", True)
    tot_l_bw_pkt = ("Total Length of Bwd Packet", "TLBwP", True)
    fw_pkt_l_max = ("Fwd Packet Length Max", "FwPLMA", True)
    fw_pkt_l_min = ("Fwd Packet Length Min", "FwPLMI", True)
    fw_pkt_l_avg = ("Fwd Packet Length Mean", "FwPLAG", True)
    fw_pkt_l_std = ("Fwd Packet Length Std", "FwPLSD", True)
    bw_pkt_l_max = ("Bwd Packet Length Max", "BwPLMA", True)
    bw_pkt_l_min = ("Bwd Packet Length Min", "BwPLMI", True)
    bw_pkt_l_avg = ("Bwd Packet Length Mean", "BwPLAG", True)
    bw_pkt_l_std = ("Bwd Packet Length Std", "BwPLSD", True)
    fl_byt_s = ("Flow Bytes/s", "FB/s", True)
    fl_pkt_s = ("Flow Packets/s", "FP/s", True)
    fl_iat_avg = ("Flow IAT Mean", "FLIATAG", True)
    fl_iat_std = ("Flow IAT Std", "FLIATSD", True)
    fl_iat_max = ("Flow IAT Max", "FLIATMA", True)
    fl_iat_min = ("Flow IAT Min", "FLIATMI", True)
    fw_iat_tot = ("Fwd IAT Total", "FwIATTO", True)
    fw_iat_avg = ("Fwd IAT Mean", "FwIATAG", True)
    fw_iat_std = ("Fwd IAT Std", "FwIATSD", True)
    fw_iat_max = ("Fwd IAT Max", "FwIATMA", True)
    fw_iat_min = ("Fwd IAT Min", "FwIATMI", True)
    bw_iat_tot = ("Bwd IAT Total", "BwIATTO", True)
    bw_iat_avg = ("Bwd IAT Mean", "BwIATAG", True)
    bw_iat_std = ("Bwd IAT Std", "BwIATSD", True)
    bw_iat_max = ("Bwd IAT Max", "BwIATMA", True)
    bw_iat_min = ("Bwd IAT Min", "BwIATMI", True)
    fw_psh_flag = ("Fwd PSH Flags", "FwPSH", True)
    bw_psh_flag = ("Bwd PSH Flags", "BwPSH", True)
    fw_urg_flag = ("Fwd URG Flags", "FwURG", True)
    bw_urg_flag = ("Bwd URG Flags", "BwURG", True)
    fw_hdr_len = ("Fwd Header Length", "FwHL", True)
    bw_hdr_len = ("Bwd Header Length", "BwHL", True)
    fw_pkt_s = ("Fwd Packets/s", "FwP/s", True)
    bw_pkt_s = ("Bwd Packets/s", "Bwp/s", True)
    pkt_len_min = ("Packet Length Min", "PLMI", True)
    pkt_len_max = ("Packet Length Max", "PLMA", True)
    pkt_len_avg = ("Packet Length Mean", "PLAG", True)
    pkt_len_std = ("Packet Length Std", "PLSD", True)
    pkt_len_var = ("Packet Length Variance", "PLVA", True)
    fin_cnt = ("FIN Flag Count", "FINCT", True)
    syn_cnt = ("SYN Flag Count", "SYNCT", True)
    rst_cnt = ("RST Flag Count", "RSTCT", True)
    pst_cnt = ("PSH Flag Count", "PSHCT", True)
    ack_cnt = ("ACK Flag Count", "ACKCT", True)
    urg_cnt = ("URG Flag Count", "URGCT", True)
    CWR_cnt = ("CWR Flag Count", "CWRCT", True)
    ece_cnt = ("ECE Flag Count", "ECECT", True)
    down_up_ratio = ("Down/Up Ratio", "D/URO", True)
    pkt_size_avg = ("Average Packet Size", "PSAG", True)
    fw_seg_avg = ("Fwd Segment Size Avg", "FwSgAG", True)
    bw_seg_avg = ("Bwd Segment Size Avg", "BwSgAG", True)
    fw_byt_blk_avg = ("Fwd Bytes/Bulk Avg", "FwB/BAG", True)
    fw_pkt_blk_avg = ("Fwd Packet/Bulk Avg", "FwP/BAG", True)
    fw_blk_rate_avg = ("Fwd Bulk Rate Avg", "FwBRAG", True)
    bw_byt_blk_avg = ("Bwd Bytes/Bulk Avg", "BwB/BAG", True)
    bw_pkt_blk_avg = ("Bwd Packet/Bulk Avg", "BwP/BAG", True)
    bw_blk_rate_avg = ("Bwd Bulk Rate Avg", "BwBRAG", True)
    subfl_fw_pkt = ("Subflow Fwd Packets", "SFFwP", True)
    subfl_fw_byt = ("Subflow Fwd Bytes", "SFFwB", True)
    subfl_bw_pkt = ("Subflow Bwd Packets", "SFBwP", True)
    subfl_bw_byt = ("Subflow Bwd Bytes", "SFBwB", True)
    fw_win_byt = ("FWD Init Win Bytes", "FwWB", True)
    bw_win_byt = ("Bwd Init Win Bytes", "BwWB", True)
    Fw_act_pkt = ("Fwd Act Data Pkts", "FwAP", True)
    fw_seg_min = ("Fwd Seg Size Min", "FwSgMI", True)
    atv_avg = ("Active Mean", "AcAG", True)
    atv_std = ("Active Std", "AcSD", True)
    atv_max = ("Active Max", "AcMA", True)
    atv_min = ("Active Min", "AcMI", True)
    idl_avg = ("Idle Mean", "IlAG", True)
    idl_std = ("Idle Std", "IlSD", True)
    idl_max = ("Idle Max", "IlMA", True)
    idl_min = ("IlMI", "IlMI", True) # Corrected abbreviation based on Java dump
    Label = ("Label", "LBL", False)

    def __init__(self, name, abbr, is_numeric):
        self._name_ = name
        self._abbr_ = abbr
        self._is_numeric_ = is_numeric

    @property
    def fullname(self):
        return self._name_

    @property
    def abbr(self):
        return self._abbr_

    @property
    def is_numeric(self):
        return self._is_numeric_

    @staticmethod
    def get_header():
        # Generate header string based on the enum order
        header = [feature.fullname for feature in FlowFeature]
        return ",".join(header)

# --- Simulate Java's MutableInt for flag counts ---
class MutableInt:
    def __init__(self, value=0):
        self.value = value

    def increment(self):
        self.value += 1

    def get(self):
        return self.value

# --- Basic Packet Information Class (based on BasicPacketInfo.java) ---
from scapy.all import Packet, IP, IPv6, TCP, UDP, Raw

class BasicPacketInfo:
    _packet_id_counter = 0

    def __init__(self, packet: Packet):
        BasicPacketInfo._packet_id_counter += 1
        self.id = BasicPacketInfo._packet_id_counter

        self.timestamp_micros = int(packet.time * 1_000_000)

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            raise ValueError("Packet does not have IP or IPv6 layer")

        self.src_ip_str = ip_layer.src
        self.dst_ip_str = ip_layer.dst
        self.protocol = ip_layer.proto

        # Get payload length from Raw layer if present, otherwise 0
        # Handle cases where Raw layer might be present but empty
        raw_layer = packet.getlayer(Raw)
        self.payload_bytes = len(raw_layer) if raw_layer is not None else 0

        # Calculate header length as total packet length minus payload length
        # This might differ slightly from the Java implementation depending on how jnetpcap calculates it,
        # but it's a standard approach in Scapy.
        self.header_bytes = len(packet) - self.payload_bytes

        # Initialize transport layer specific attributes
        self.src_port = None
        self.dst_port = None
        self.flagFIN = False
        self.flagPSH = False
        self.flagURG = False
        self.flagECE = False
        self.flagSYN = False
        self.flagACK = False
        self.flagCWR = False
        self.flagRST = False
        self.tcp_window = 0 # Default window size for non-TCP

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            self.src_port = tcp_layer.sport
            self.dst_port = tcp_layer.dport
            # Check flags using getattr to safely access flags attribute
            self.flagFIN = getattr(tcp_layer.flags, 'F', False)
            self.flagPSH = getattr(tcp_layer.flags, 'P', False)
            self.flagURG = getattr(tcp_layer.flags, 'U', False)
            self.flagECE = getattr(tcp_layer.flags, 'E', False)
            self.flagSYN = getattr(tcp_layer.flags, 'S', False)
            self.flagACK = getattr(tcp_layer.flags, 'A', False)
            self.flagCWR = getattr(tcp_layer.flags, 'C', False)
            self.flagRST = getattr(tcp_layer.flags, 'R', False)
            self.tcp_window = tcp_layer.window

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            self.src_port = udp_layer.sport
            self.dst_port = udp_layer.dport
            # UDP has no flags or window size


        self.flow_id = None # Will be generated on demand


    def getSourceIP(self):
        return self.src_ip_str

    def getDestinationIP(self):
        return self.dst_ip_str

    def fwdFlowId(self):
        # Generate forward flow ID (SrcIP-DstIP-SrcPort-DstPort-Protocol)
        # Ensure ports are handled correctly if None (e.g., for non-TCP/UDP packets, though filtered earlier)
        src_p = self.src_port if self.src_port is not None else 0
        dst_p = self.dst_port if self.dst_port is not None else 0
        return f"{self.getSourceIP()}-{self.getDestinationIP()}-{src_p}-{dst_p}-{self.getProtocol()}"

    def bwdFlowId(self):
        # Generate backward flow ID (DstIP-SrcIP-DstPort-SrcPort-Protocol)
        # Ensure ports are handled correctly if None
        src_p = self.src_port if self.src_port is not None else 0
        dst_p = self.dst_port if self.dst_port is not None else 0
        return f"{self.getDestinationIP()}-{self.getSourceIP()}-{dst_p}-{src_p}-{self.getProtocol()}"


    def generateFlowId(self):
        # Determine direction and generate the direction-independent flow ID
        # This logic mirrors the byte-by-byte comparison in Java by comparing string representations
        # This might not be 100% identical to byte comparison for all IP address types/formats
        # but is the closest direct translation using string IPs.
        # Ensure ports are handled correctly if None for comparison
        src_tuple = (self.src_ip_str, self.src_port if self.src_port is not None else 0)
        dst_tuple = (self.dst_ip_str, self.dst_port if self.dst_port is not None else 0)

        if src_tuple > dst_tuple:
             self.flow_id = self.bwdFlowId()
        else:
             self.flow_id = self.fwdFlowId()

        return self.flow_id


    def getFlowId(self):
        if self.flow_id is None:
            return self.generateFlowId()
        return self.flow_id

    def isForwardPacket(self, flow_src_ip_string):
        # Check if the packet's source matches the flow's designated source IP string
        # This requires the flow's src IP to be set externally before calling
        # Check if flow_src_ip_string is None or empty before comparison
        if flow_src_ip_string is None or flow_src_ip_string == "":
             # This indicates a problem in flow initialization if called on an active flow
             logger.warning(f"isForwardPacket called with invalid flow_src_ip_string: {flow_src_ip_string}")
             return False # Cannot determine direction without flow src
        return self.getSourceIP() == flow_src_ip_string

    def getTimeStamp(self):
        return self.timestamp_micros

    def hasFlagFIN(self): return self.flagFIN
    def hasFlagPSH(self): return self.flagPSH
    def hasFlagURG(self): return self.flagURG
    def hasFlagECE(self): return self.flagECE
    def hasFlagSYN(self): return self.flagSYN
    def hasFlagACK(self): return self.flagACK
    def hasFlagCWR(self): return self.flagCWR
    def hasFlagRST(self): return self.flagRST
    def getTCPWindow(self): return self.tcp_window
    def getPayloadBytes(self): return self.payload_bytes
    def getHeaderBytes(self): return self.header_bytes
    def getSrcPort(self): return self.src_port if self.src_port is not None else 0 # Return 0 if port is None
    def getDstPort(self): return self.dst_port if self.dst_port is not None else 0 # Return 0 if port is None
    def getProtocol(self): return self.protocol


# --- Basic Flow Representation (Equivalent to BasicFlow.java) ---
class BasicFlow:
    def __init__(self, isBidirectional: bool, packet: BasicPacketInfo, flowSrc: str = None, flowDst: str = None, flowSrcPort: int = None, flowDstPort: int = None, activityTimeout: int = IDLE_TIMEOUT_MICROS):
        logger.debug(f"BasicFlow __init__ start for packet id {packet.id}, object id: {id(self)}")
        self.activityTimeout = activityTimeout

        # Initialize identity attributes first (before initParameters)
        self.src = None
        self.dst = None
        self.srcPort = 0
        self.dstPort = 0
        self.protocol = 0
        self.flowId = None

        self.isBidirectional = isBidirectional

        # Determine and set the flow's identity based on constructor arguments or the first packet
        # This block executes for *all* BasicFlow instantiations
        if flowSrc is not None: # Case 1: Flow identity explicitly provided (e.g., after timeout)
            logger.debug("BasicFlow __init__: Using provided identity.")
            self.src = flowSrc
            self.dst = flowDst
            self.srcPort = flowSrcPort
            self.dstPort = flowDstPort
            # Protocol and FlowId are still derived from the first packet below
        else: # Case 2: New flow detection - identity based *solely* on the first packet's direction
            logger.debug("BasicFlow __init__: Determining identity from first packet.")
            # Use the BasicPacketInfo's generateFlowId to get the canonical direction
            packet.generateFlowId() # Ensure the canonical flow ID is determined

            packet_src_ip = packet.getSourceIP()
            packet_dst_ip = packet.getDestinationIP()
            packet_src_port = packet.getSrcPort()
            packet_dst_port = packet.getDstPort()

            logger.debug(f"Packet {packet.id} details: src={packet_src_ip}:{packet_src_port}, dst={packet_dst_ip}:{packet_dst_port}")

            # Determine flow src/dst based on the canonical flow ID direction derived from the first packet
            src_tuple = (packet_src_ip, packet_src_port)
            dst_tuple = (packet_dst_ip, packet_dst_port)

            # Compare tuples to establish canonical flow direction (src is the "lower" endpoint)
            if src_tuple > dst_tuple:
                 logger.debug("Packet source is backward relative to canonical flow ID.")
                 self.src = packet_dst_ip
                 self.dst = packet_src_ip
                 self.srcPort = packet_dst_port
                 self.dstPort = packet_src_port
            else:
                 logger.debug("Packet source is forward relative to canonical flow ID.")
                 self.src = packet_src_ip
                 self.dst = packet_dst_ip
                 self.srcPort = packet_src_port
                 self.dstPort = packet_dst_port

        # Protocol is always taken from the first packet
        self.protocol = packet.getProtocol()
        # Flow ID is always the canonical ID derived from the first packet
        self.flowId = packet.getFlowId()

        logger.debug(f"BasicFlow __init__: Flow identity set. src={self.src}, dst={self.dst}, id={self.flowId}")

        # Now, call initParameters() to initialize all stats and counters
        # This method will now rely on self.src, self.dst etc. being already set.
        self.initParameters()
        logger.debug(f"BasicFlow __init__ after initParameters. self.src={self.src}")


        # Finally, process the first packet using the firstPacket method
        # firstPacket will add the packet's data to the lists and update initial stats/times.
        self.firstPacket(packet)
        logger.debug(f"BasicFlow __init__ finished for packet id {packet.id}, object id: {id(self)})")


    def initParameters(self):
        logger.debug(f"BasicFlow.initParameters called for object {id(self)}. Flow ID: {self.flowId}")
        # Initialize lists and SummaryStatistics equivalents
        self.forward = []
        self.backward = []
        self.flowIAT = []
        self.forwardIAT = []
        self.backwardIAT = []
        self.flowLengthStats = []
        self.flowActive = []
        self.flowIdle = []
        self.fwdPktStats = [] # Stores payload lengths
        self.bwdPktStats = [] # Stores payload lengths

        # Initialize flag counts
        self.flagCounts = {}
        self.initFlags() # Initialize the flagCounts dictionary with MutableInts
        logger.debug(f"BasicFlow.initParameters: initFlags called and finished.")

        # Defensive check: Ensure checkFlags method exists immediately after initFlags
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside initParameters for object {id(self)}, 'checkFlags' method is missing AFTER initFlags!")
             # Raise a specific exception here if it occurs, which would be a severe issue
             # raise AttributeError(f"'BasicFlow' object unexpectedly missing 'checkFlags' method in initParameters for object {id(self)}")

        # Initialize byte and header counts
        self.forwardBytes = 0
        self.backwardBytes = 0
        self.fHeaderBytes = 0
        self.bHeaderBytes = 0

        # Initialize directional flag counters (used for features)
        self.fPSH_cnt = 0
        self.bPSH_cnt = 0
        self.fURG_cnt = 0
        self.bURG_cnt = 0
        self.fFIN_cnt = 0
        self.bFIN_cnt = 0


        # Initialize other specific features/helpers
        self.min_seg_size_forward = float('inf')
        self.Act_data_pkt_forward = 0
        self.Init_Win_bytes_forward = 0
        self.Init_Win_bytes_backward = 0

        # Initialize time tracking variables
        # flowStartTime, flowLastSeen are set in firstPacket
        self.flowStartTime = 0
        self.flowLastSeen = 0
        self.forwardLastSeen = 0
        self.backwardLastSeen = 0

        # Active and Idle Time Tracking
        self.startActiveTime = 0 # These are set in firstPacket initially
        self.endActiveTime = 0
        self._current_activity_start_time = 0 # Helper, also set in firstPacket

        # Bulk related parameters - initialized to 0/None by default
        self.fbulkDuration=0
        self.fbulkPacketCount=0
        self.fbulkSizeTotal=0
        self.fbulkStateCount=0
        self.fbulkPacketCountHelper=0
        self.fbulkStartHelper=0
        self.fbulkSizeHelper=0
        self.flastBulkTS=0
        self.bbulkDuration=0
        self.bbulkPacketCount=0
        self.bbulkSizeTotal=0
        self.bbulkStateCount=0
        self.bbulkPacketCountHelper=0
        self.bbulkStartHelper=0
        self.bbulkSizeHelper=0
        self.blastBulkTS=0

        # Subflow related parameters - initialized to -1/0 by default
        self.sfLastPacketTS = -1
        self.sfCount = 0
        self.sfAcHelper = -1

        logger.debug(f"BasicFlow.initParameters finished for object {id(self)}")


    def initFlags(self):
        logger.debug(f"BasicFlow.initFlags called for object {id(self)}")
        # Initialize counts for all TCP flags in the flagCounts dictionary
        self.flagCounts["FIN"] = MutableInt()
        self.flagCounts["SYN"] = MutableInt()
        self.flagCounts["RST"] = MutableInt()
        self.flagCounts["PSH"] = MutableInt()
        self.flagCounts["ACK"] = MutableInt()
        self.flagCounts["URG"] = MutableInt()
        self.flagCounts["CWR"] = MutableInt()
        self.flagCounts["ECE"] = MutableInt()
        logger.debug(f"BasicFlow.initFlags finished for object {id(self)}")


    def firstPacket(self, packet: BasicPacketInfo):
        logger.debug(f"BasicFlow.firstPacket called for object {id(self)}. Packet timestamp: {packet.getTimeStamp()}")
        # Process the very first packet of the flow
        # ASSUMPTION: self.src, self.dst, etc., are ALREADY set by the __init__ method before this is called.
        # This method focuses on initializing stats and times based on this first packet.

        # Defensive check: Ensure checkFlags method exists before calling it
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside firstPacket for object {id(self)}, 'checkFlags' method is missing BEFORE calling it!")
             # Raise a specific exception here if it occurs to stop processing and inspect
             raise AttributeError(f"'BasicFlow' object unexpectedly missing 'checkFlags' method in firstPacket for object {id(self)}. State: {getattr(self, '__dict__', 'N/A')}")


        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)
        logger.debug(f"BasicFlow.firstPacket about to call checkFlags for object {id(self)}")
        self.checkFlags(packet) # <--- Error occurring here

        # Initialize times based on the first packet's timestamp
        self.flowStartTime = packet.getTimeStamp()
        self.flowLastSeen = packet.getTimeStamp()
        self.startActiveTime = packet.getTimeStamp() # Start of first active period
        self.endActiveTime = packet.getTimeStamp() # End of first active period
        self._current_activity_start_time = packet.getTimeStamp() # Initialize helper

        # Add the first packet's payload length to the total flow length stats
        self.flowLengthStats.append(packet.getPayloadBytes())

        # Add the first packet's stats to forward/backward based on the flow direction already determined in __init__
        # Use the isForwardPacket method, which relies on self.src being set.
        if packet.isForwardPacket(self.src):
            logger.debug(f"Packet {packet.id} is FORWARD in flow {self.flowId}")
            # Ensure min_seg_size_forward is only updated if packet has header bytes > 0
            if packet.getHeaderBytes() > 0:
                 self.min_seg_size_forward = min(self.min_seg_size_forward, packet.getHeaderBytes())

            self.Init_Win_bytes_forward = packet.getTCPWindow() # Only set by first forward packet with window > 0
            self.fwdPktStats.append(packet.getPayloadBytes())
            self.fHeaderBytes += packet.getHeaderBytes()
            self.forward.append(packet) # Add packet to forward list
            self.forwardBytes += packet.getPayloadBytes()
            self.forwardLastSeen = packet.getTimeStamp()
            # Directional PSH/URG counts were incremented in checkFlags already based on Java structure

        else: # Backward packet
            logger.debug(f"Packet {packet.id} is BACKWARD in flow {self.flowId}")
            # Init_Win_bytes_backward is only set by the *first* backward packet with window > 0.
            # Check again here in case the first backward packet didn't have window > 0.
            if self.Init_Win_bytes_backward == 0 and packet.getTCPWindow() > 0:
                 self.Init_Win_bytes_backward = packet.getTCPWindow()

            self.bwdPktStats.append(packet.getPayloadBytes())
            self.bHeaderBytes += packet.getHeaderBytes()
            self.backward.append(packet) # Add packet to backward list
            self.backwardBytes += packet.getPayloadBytes()
            self.backwardLastSeen = packet.getTimeStamp() # Update last timestamp in backward direction
            # Directional PSH/URG counts were incremented in checkFlags already based on Java structure

        # Add to total flow length stats (payload length) for bidirectional flows
        # Note: For unidirectional, flowLengthStats only gets forward packet lengths,
        # which is handled in firstPacket and the unidirectional block of addPacket.
        if self.isBidirectional:
             # This was already done once above before the directional split.
             # Let's remove this duplicate append.
             pass # self.flowLengthStats.append(packet.getPayloadBytes()) # REMOVE THIS DUPLICATE


        logger.debug(f"BasicFlow.firstPacket finished for object {id(self)}")


    def addPacket(self, packet: BasicPacketInfo):
        logger.debug(f"BasicFlow.addPacket called for flow {self.getFlowId()} (object id: {id(self)}). Packet timestamp: {packet.getTimeStamp()}, Packet id: {packet.id}")
        # Process subsequent packets in the flow

        # Defensive check: Ensure this flow object is valid before proceeding
        if not hasattr(self, 'checkFlags') or not callable(getattr(self, 'checkFlags', None)):
             logger.error(f"CRITICAL ERROR: Inside addPacket for object {id(self)}, 'checkFlags' method is missing! Skipping packet {packet.id}")
             # Log the object's state for debugging
             try:
                  logger.error(f"Malformed Flow Object State for ID {id(self)}: {getattr(self, '__dict__', 'N/A')}")
             except Exception:
                  pass
             return # Skip processing this packet for this apparently invalid flow object


        # Update state variables based on the new packet
        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)
        self.checkFlags(packet) # This updates global flag counts and directional PSH/URG counts

        currentTimestamp = packet.getTimeStamp()

        # Update active/idle times based on the arrival of this packet
        self.updateActiveIdleTime(currentTimestamp, self.activityTimeout)

        # Calculate Flow IAT
        if self.flowLastSeen != 0: # Should always be true after the first packet
             self.flowIAT.append(currentTimestamp - self.flowLastSeen)
        self.flowLastSeen = currentTimestamp # Update the timestamp of the last packet seen by the flow


        # Add packet stats to appropriate direction
        # Determine direction based on the flow's established src IP
        if packet.isForwardPacket(self.src):
            logger.debug(f"Packet {packet.id} is FORWARD in flow {self.flowId}")
            if packet.getPayloadBytes() >= 1:
                self.Act_data_pkt_forward += 1 # Count forward packets with payload >= 1
            self.fwdPktStats.append(packet.getPayloadBytes())
            self.fHeaderBytes += packet.getHeaderBytes()
            self.forward.append(packet) # Add packet to forward list
            self.forwardBytes += packet.getPayloadBytes()
            if len(self.forward) > 1: # IAT is between this packet and the previous forward packet
                self.forwardIAT.append(currentTimestamp - self.forwardLastSeen)
            self.forwardLastSeen = currentTimestamp # Update last timestamp in forward direction
            # Ensure min_seg_size_forward is updated only if packet has header bytes > 0
            if packet.getHeaderBytes() > 0:
                 self.min_seg_size_forward = min(self.min_seg_size_forward, packet.getHeaderBytes())

        else: # Backward packet
            logger.debug(f"Packet {packet.id} is BACKWARD in flow {self.flowId}")
            self.bwdPktStats.append(packet.getPayloadBytes())
            # Init_Win_bytes_backward is only set by the *first* backward packet with window > 0.
            # Check again here in case the first backward packet didn't have window > 0.
            if self.Init_Win_bytes_backward == 0 and packet.getTCPWindow() > 0:
                 self.Init_Win_bytes_backward = packet.getTCPWindow()

            self.bHeaderBytes += packet.getHeaderBytes()
            self.backward.append(packet) # Add packet to backward list
            self.backwardBytes += packet.getPayloadBytes()
            if len(self.backward) > 1: # IAT is between this packet and the previous backward packet
                self.backwardIAT.append(currentTimestamp - self.backwardLastSeen)
            self.backwardLastSeen = currentTimestamp # Update last timestamp in backward direction

        # Add to total flow length stats (payload length) for bidirectional flows
        # Note: For unidirectional, flowLengthStats only gets forward packet lengths,
        # which is handled in firstPacket and the unidirectional block of addPacket.
        if self.isBidirectional:
             self.flowLengthStats.append(packet.getPayloadBytes())

        logger.debug(f"BasicFlow.addPacket finished for object {id(self)}. Flow ID: {self.flowId}")


    # --- Bulk and Subflow Calculations (Translating Java Logic) ---
    # These methods are called from addPacket and firstPacket.
    # The getter methods below read the state variables updated by these methods.
    def updateFlowBulk(self, packet: BasicPacketInfo):
        # Direct translation of the Java logic for updating bulk state
        # Determine direction based on the flow's established src IP
        if packet.isForwardPacket(self.src):
            self.updateForwardBulk(packet, self.blastBulkTS)
        else:
            self.updateBackwardBulk(packet, self.flastBulkTS)

    def updateForwardBulk(self, packet: BasicPacketInfo, tsOflastBulkInOther: int):
        # Direct translation of the Java logic for updating forward bulk state
        size = packet.getPayloadBytes()
        # If last bulk in OTHER direction is after the start of current potential bulk, reset helper
        if tsOflastBulkInOther > self.fbulkStartHelper: self.fbulkStartHelper = 0
        if size <= 0: return # Only consider packets with payload

        if self.fbulkStartHelper == 0:
            # Start of a potential new bulk
            self.fbulkStartHelper = packet.getTimeStamp()
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = size
            self.flastBulkTS = packet.getTimeStamp()
        else:
            # Check if the time gap is too large to be part of the same bulk (1 second threshold)
            if ((packet.getTimeStamp() - self.flastBulkTS) / 1_000_000.0) > 1.0:
                # Gap too large, start a new potential bulk
                self.fbulkStartHelper = packet.getTimeStamp()
                self.flastBulkTS = packet.getTimeStamp()
                self.fbulkPacketCountHelper = 1
                self.fbulkSizeHelper = size
            else:
                # Add packet to the current potential bulk
                self.fbulkPacketCountHelper += 1
                self.fbulkSizeHelper += size
                # If helper count reaches 4, a new bulk is confirmed. Add helper stats to total bulk stats.
                if self.fbulkPacketCountHelper == 4:
                    self.fbulkStateCount += 1 # Increment bulk count
                    self.fbulkPacketCount += self.fbulkPacketCountHelper # Add packets from helper
                    self.fbulkSizeTotal += self.fbulkSizeHelper # Add size from helper
                    self.fbulkDuration += packet.getTimeStamp() - self.fbulkStartHelper # Add duration of this bulk
                # If helper count exceeds 4, it's a continuation of an existing bulk. Add this packet's stats directly.
                elif self.fbulkPacketCountHelper > 4:
                    self.fbulkPacketCount += 1 # Just count this packet
                    self.fbulkSizeTotal += size # Add this packet's size
                    self.fbulkDuration += packet.getTimeStamp() - self.flastBulkTS # Add IAT since last packet in bulk
                self.flastBulkTS = packet.getTimeStamp() # Update last timestamp in bulk


    def updateBackwardBulk(self, packet: BasicPacketInfo, tsOflastBulkInOther: int):
        # Direct translation of the Java logic for updating backward bulk state
        size = packet.getPayloadBytes()
        # If last bulk in OTHER direction is after the start of current potential bulk, reset helper
        if tsOflastBulkInOther > self.bbulkStartHelper: self.bbulkStartHelper = 0
        if size <= 0: return # Only consider packets with payload

        if self.bbulkStartHelper == 0:
            # Start of a potential new bulk
            self.bbulkStartHelper = packet.getTimeStamp()
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = size
            self.blastBulkTS = packet.getTimeStamp()
        else:
            # Check if the time gap is too large to be part of the same bulk (1 second threshold)
            if ((packet.getTimeStamp() - self.blastBulkTS) / 1_000_000.0) > 1.0:
                # Gap too large, start a new potential bulk
                self.bbulkStartHelper = packet.getTimeStamp()
                self.blastBulkTS = packet.getTimeStamp()
                self.bbulkPacketCountHelper = 1
                self.bbulkSizeHelper = size
            else:
                # Add packet to the current potential bulk
                self.bbulkPacketCountHelper += 1
                self.bbulkSizeHelper += size
                # If helper count reaches 4, a new bulk is confirmed. Add helper stats to total bulk stats.
                if self.bbulkPacketCountHelper == 4:
                    self.bbulkStateCount += 1 # Increment bulk count
                    self.bbulkPacketCount += self.bbulkPacketCountHelper # Add packets from helper
                    self.bbulkSizeTotal += self.bbulkSizeHelper # Add size from helper
                    self.bbulkDuration += packet.getTimeStamp() - self.bbulkStartHelper # Add duration of this bulk
                # If helper count exceeds 4, it's a continuation of an existing bulk. Add this packet's stats directly.
                elif self.bbulkPacketCountHelper > 4:
                    self.bbulkPacketCount += 1 # Just count this packet
                    self.bbulkSizeTotal += size # Add this packet's size
                    self.bbulkDuration += packet.getTimeStamp() - self.blastBulkTS # Add IAT since last packet in bulk
                self.blastBulkTS = packet.getTimeStamp() # Update last timestamp in bulk


    def detectUpdateSubflows(self, packet: BasicPacketInfo):
        # Direct translation of the Java logic for detecting and updating subflows
        if self.sfLastPacketTS == -1:
            self.sfLastPacketTS = packet.getTimeStamp()
            self.sfAcHelper = packet.getTimeStamp()

        # Subflow is detected if the time gap between the current and last packet is > 1 second
        if ((packet.getTimeStamp() - self.sfLastPacketTS) / 1_000_000.0) > 1.0:
            self.sfCount += 1 # Increment subflow count
            # This call marks the end of the *previous* active period and the start of a new one, based on the subflow boundary (1-second idle time).
            self.updateActiveIdleTime(packet.getTimeStamp(), self.activityTimeout)
            self.sfAcHelper = packet.getTimeStamp() # Reset the subflow active helper timestamp

        self.sfLastPacketTS = packet.getTimeStamp() # Update the timestamp of the last packet seen by subflow detection


    # --- Active and Idle Time Calculations (Translating Java Logic) ---
    def updateActiveIdleTime(self, currentTime: int, threshold: int):
        logger.debug(f"BasicFlow.updateActiveIdleTime called for flow {self.flowId} (object id: {id(self)}). CurrentTime: {currentTime}, Threshold: {threshold}, EndActiveTime: {self.endActiveTime}")
        # Direct translation of the Java logic for updating active/idle time state
        # If the time since the last packet in the flow (endActiveTime) exceeds the activity threshold (IDLE_TIMEOUT_MICROS)
        if (self.endActiveTime > 0) and ((currentTime - self.endActiveTime) > threshold): # Add check for endActiveTime > 0
            logger.debug(f"BasicFlow.updateActiveIdleTime: Idle period detected. Duration: {currentTime - self.endActiveTime}")
            # The previous period was an active period ending at endActiveTime. Record its duration if positive.
            if (self.endActiveTime - self.startActiveTime) > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)

            # The period between endActiveTime and currentTime is an idle period. Record its duration.
            self.flowIdle.append(currentTime - self.endActiveTime)

            # Start a new active period at the current packet's time
            self.startActiveTime = currentTime
            self.endActiveTime = currentTime
            logger.debug(f"BasicFlow.updateActiveIdleTime: New active period started at {self.startActiveTime}")
        else:
            # The current packet arrived within the activity threshold, extend the current active period
            self.endActiveTime = currentTime # Update the end time of the current active period
            # Initialize startActiveTime if it's the first packet (endActiveTime was 0)
            if self.startActiveTime == 0:
                 self.startActiveTime = currentTime
            logger.debug(f"BasicFlow.updateActiveIdleTime: Active period extended to {self.endActiveTime}")


    def endActiveIdleTime(self, currentTime: int, threshold: int, flowTimeOut: int, isFlagEnd: bool):
        logger.debug(f"BasicFlow.endActiveIdleTime called for flow {self.flowId} (object id: {id(self)}). CurrentTime: {currentTime}, IsFlagEnd: {isFlagEnd}")
        # Direct translation of the Java logic for finalizing active/idle times
        # This is called when a flow terminates.

        # Finalize the last active period (if any)
        if (self.endActiveTime - self.startActiveTime) > 0:
            self.flowActive.append(self.endActiveTime - self.startActiveTime)
            logger.debug(f"BasicFlow.endActiveIdleTime: Final active period duration: {self.endActiveTime - self.startActiveTime}")


        # This part of the idle time calculation seems to add remaining flow timeout as idle time if not ended by a flag.
        # Replicating it directly as per the Java code's dump method context.
        # The logic is: if the flow was NOT ended by a FIN/RST flag, AND the duration from the flow start
        # to the end of the *last active period* is less than the overall flow timeout, then
        # the difference between the flow timeout and the duration of the last active period
        # is added as an idle time. This seems intended to account for the final idle period
        # until the flow timeout would have occurred.
        if not isFlagEnd: # If flow was NOT terminated by a flag (i.e., by timeout or end of file)
             duration_until_last_active_end = self.endActiveTime - self.flowStartTime
             # Check if the potential remaining time after the last active period is positive
             potential_remaining_idle = flowTimeOut - duration_until_last_active_end
             logger.debug(f"BasicFlow.endActiveIdleTime: Flow not flag ended. Potential remaining idle: {potential_remaining_idle}")
             # Only add positive idle times and if the last active period didn't cover the entire flow duration
             if potential_remaining_idle > 0 and duration_until_last_active_end < (self.flowLastSeen - self.flowStartTime): # Add extra check
                  self.flowIdle.append(potential_remaining_idle)
                  logger.debug(f"BasicFlow.endActiveIdleTime: Added remaining idle time: {potential_remaining_idle}")

        logger.debug(f"BasicFlow.endActiveIdleTime finished for flow {self.flowId}")


    # --- Feature Calculation Methods (Translating Java Getters and dump method logic) ---

    def packetCount(self) -> int:
        # Total packet count (forward + backward)
        return len(self.forward) + len(self.backward)

    def getFlowStartTime(self) -> int:
        # Flow start timestamp in microseconds
        return self.flowStartTime

    def getSrc(self) -> str:
        # Flow's designated source IP address string
        return self.src

    def getDst(self) -> str:
        # Flow's designated destination IP address string
        return self.dst

    def getSrcPort(self) -> int:
        # Flow's designated source port
        # Return 0 if port was None (e.g., non-TCP/UDP)
        return self.srcPort if self.srcPort is not None else 0

    def getDstPort(self) -> int:
        # Flow's designated destination port
         # Return 0 if port was None (e.g., non-TCP/UDP)
        return self.dstPort if self.dstPort is not None else 0

    def getProtocol(self) -> int:
        # Flow's protocol number
        return self.protocol

    def getProtocolStr(self) -> str:
        # Used for debugging/logging, not in the CSV dump
        if self.protocol == 6: return "TCP"
        if self.protocol == 17: return "UDP"
        return "UNKNOWN"

    def getFlowId(self) -> str:
        # Canonical flow ID string
        return self.flowId

    def getFlowDuration(self) -> int:
        # Flow duration in microseconds
        return self.flowLastSeen - self.flowStartTime

    def getTotalFwdPackets(self) -> int:
        # Total number of forward packets
        return len(self.forward)

    def getTotalBackwardPackets(self) -> int:
        # Total number of backward packets
        return len(self.backward)

    def getTotalLengthofFwdPackets(self) -> int:
        # Total payload bytes in forward packets
        return self.forwardBytes

    def getTotalLengthofBwdPackets(self) -> int:
        # Total payload bytes in backward packets
        return self.backwardBytes

    def getFwdPacketLengthMax(self) -> float:
        return max(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthMin(self) -> float:
        return min(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthMean(self) -> float:
        return statistics.mean(self.fwdPktStats) if self.fwdPktStats else 0.0

    def getFwdPacketLengthStd(self) -> float:
        return statistics.stdev(self.fwdPktStats) if len(self.fwdPktStats) > 1 else 0.0

    def getBwdPacketLengthMax(self) -> float:
        return max(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthMin(self) -> float:
        return min(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthMean(self) -> float:
        return statistics.mean(self.bwdPktStats) if self.bwdPktStats else 0.0

    def getBwdPacketLengthStd(self) -> float:
        return statistics.stdev(self.bwdPktStats) if len(self.bwdPktStats) > 1 else 0.0

    def getFlowBytesPerSec(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return (self.forwardBytes + self.backwardBytes) / (flowDuration / 1_000_000.0)
        return 0.0

    def getFlowPacketsPerSec(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return self.packetCount() / (flowDuration / 1_000_000.0)
        return 0.0

    def getFlowIATMean(self) -> float:
        return statistics.mean(self.flowIAT) if self.flowIAT else 0.0

    def getFlowIATStd(self) -> float:
        return statistics.stdev(self.flowIAT) if len(self.flowIAT) > 1 else 0.0

    def getFlowIATMax(self) -> float:
        return max(self.flowIAT) if self.flowIAT else 0.0

    def getFlowIATMin(self) -> float:
        return min(self.flowIAT) if self.flowIAT else 0.0

    def getFwdIATTotal(self) -> int:
        # Sum of forward inter-arrival times
        return sum(self.forwardIAT) if self.forwardIAT else 0

    def getFwdIATMean(self) -> float:
        return statistics.mean(self.forwardIAT) if self.forwardIAT else 0.0

    def getFwdIATStd(self) -> float:
        return statistics.stdev(self.forwardIAT) if len(self.forwardIAT) > 1 else 0.0

    def getFwdIATMax(self) -> float:
        return max(self.forwardIAT) if self.forwardIAT else 0.0

    def getFwdIATMin(self) -> float:
        return min(self.forwardIAT) if self.forwardIAT else 0.0

    def getBwdIATTotal(self) -> int:
        # Sum of backward inter-arrival times
        return sum(self.backwardIAT) if self.backwardIAT else 0

    def getBwdIATMean(self) -> float:
        return statistics.mean(self.backwardIAT) if self.backwardIAT else 0.0

    def getBwdIATStd(self) -> float:
        return statistics.stdev(self.backwardIAT) if len(self.backwardIAT) > 1 else 0.0

    def getBwdIATMax(self) -> float:
        return max(self.backwardIAT) if self.backwardIAT else 0.0

    def getBwdIATMin(self) -> float:
        return min(self.backwardIAT) if self.backwardIAT else 0.0

    def getFwdPSHFlags(self) -> int:
        return self.fPSH_cnt

    def getBwdPSHFlags(self) -> int:
        return self.bPSH_cnt

    def getFwdURGFlags(self) -> int:
        return self.fURG_cnt

    def getBwdURGFlags(self) -> int:
        return self.bURG_cnt

    # FIN flag counts used in termination logic, distinct from the global FIN count feature
    def getFwdFINFlags(self) -> int:
        return self.fFIN_cnt

    def getBwdFINFlags(self) -> int:
        return self.bFIN_cnt

    # Methods to increment directional FIN flags (used in FlowGenerator)
    def setFwdFINFlags(self) -> int:
        self.fFIN_cnt += 1
        return self.fFIN_cnt

    def setBwdFINFlags(self) -> int:
        self.bFIN_cnt += 1
        return self.bFIN_cnt

    def getFwdHeaderLength(self) -> int:
        # Total forward header bytes
        return self.fHeaderBytes

    def getBwdHeaderLength(self) -> int:
        # Total backward header bytes
        return self.bHeaderBytes

    def getfPktsPerSecond(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return len(self.forward) / (flowDuration / 1_000_000.0)
        return 0.0

    def getbPktsPerSecond(self) -> float:
        flowDuration = self.getFlowDuration()
        if flowDuration > 0:
            # Java divides by duration in seconds (micros / 1_000_000)
            return len(self.backward) / (flowDuration / 1_000_000.0)
        return 0.0

    def getPacketLengthMin(self) -> float:
        # Min payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return min(all_lengths) if all_lengths else 0.0

    def getPacketLengthMax(self) -> float:
        # Max payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return max(all_lengths) if all_lengths else 0.0

    def getPacketLengthMean(self) -> float:
        # Mean payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.mean(all_lengths) if all_lengths else 0.0

    def getPacketLengthStd(self) -> float:
        # Std Dev of payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.stdev(all_lengths) if len(all_lengths) > 1 else 0.0

    def getPacketLengthVariance(self) -> float:
        # Variance of payload length across all packets
        all_lengths = self.fwdPktStats + self.bwdPktStats
        return statistics.variance(all_lengths) if len(all_lengths) > 1 else 0.0

    def getFlagCount(self, key: str) -> int:
        # Get global flag count by key (total occurrences across all packets)
        return self.flagCounts.get(key, MutableInt()).get()

    # Global Flag Count Getters
    def getFINFlagCount(self) -> int: return self.getFlagCount("FIN")
    def getSYNFlagCount(self) -> int: return self.getFlagCount("SYN")
    def getRSTFlagCount(self) -> int: return self.getFlagCount("RST")
    def getPSHFlagCount(self) -> int: return self.getFlagCount("PSH")
    def getACKFlagCount(self) -> int: return self.getFlagCount("ACK")
    def getURGFlagCount(self) -> int: return self.getFlagCount("URG")
    def getCWRFlagCount(self) -> int: return self.getFlagCount("CWR")
    def getECEFlagCount(self) -> int: return self.getFlagCount("ECE")


    def getDownUpRatio(self) -> float:
        # Ratio of backward packets to forward packets
        if len(self.forward) > 0:
            return len(self.backward) / len(self.forward)
        return 0.0

    def getAveragePacketSize(self) -> float:
        # Average payload size across all packets (sum of payload lengths / total packet count)
        # This is distinct from PacketLengthMean, which is mean of the list of lengths.
        # Following the Java calculation flowLengthStats.getSum() / packetCount()
        total_bytes = sum(self.flowLengthStats) # Sum of payload lengths
        total_packets = self.packetCount()
        return total_bytes / total_packets if total_packets > 0 else 0.0


    def fAvgSegmentSize(self) -> float:
        # Average forward payload size (sum of forward payload lengths / forward packet count)
        if len(self.forward) > 0:
            return sum(self.fwdPktStats) / len(self.forward)
        return 0.0

    def bAvgSegmentSize(self) -> float:
        # Average backward payload size (sum of backward payload lengths / backward packet count)
        if len(self.backward) > 0:
            return sum(self.bwdPktStats) / len(self.backward)
        return 0.0

    # Bulk Feature Getters (read the state variables updated by updateFlowBulk methods)
    def fbulkStateCount_getter(self) -> int: return self.fbulkStateCount # Number of forward bulks detected
    def fbulkSizeTotal_getter(self) -> int: return self.fbulkSizeTotal # Total bytes in forward bulks
    def fbulkPacketCount_getter(self) -> int: return self.fbulkPacketCount # Total packets in forward bulks
    def fbulkDuration_getter(self) -> int: return self.fbulkDuration # Total duration of forward bulks in micros
    def fbulkDurationInSecond(self) -> float:
        return self.fbulkDuration / 1_000_000.0

    def fAvgBytesPerBulk(self) -> float:
        if self.fbulkStateCount_getter() != 0:
            return self.fbulkSizeTotal_getter() / self.fbulkStateCount_getter()
        return 0.0

    def fAvgPacketsPerBulk(self) -> float:
        if self.fbulkStateCount_getter() != 0:
            return self.fbulkPacketCount_getter() / self.fbulkStateCount_getter()
        return 0.0

    def fAvgBulkRate(self) -> float:
        if self.fbulkDuration_getter() != 0:
            # Rate in bytes per second
            return self.fbulkSizeTotal_getter() / self.fbulkDurationInSecond()
        return 0.0

    def bbulkPacketCount_getter(self) -> int: return self.bbulkPacketCount
    def bbulkStateCount_getter(self) -> int: return self.bbulkStateCount
    def bbulkSizeTotal_getter(self) -> int: return self.bbulkSizeTotal
    def bbulkDuration_getter(self) -> int: return self.bbulkDuration
    def bbulkDurationInSecond(self) -> float:
        return self.bbulkDuration / 1_000_000.0

    def bAvgBytesPerBulk(self) -> float:
        if self.bbulkStateCount_getter() != 0:
            return self.bbulkSizeTotal_getter() / self.bbulkStateCount_getter()
        return 0.0

    def bAvgPacketsPerBulk(self) -> float:
        if self.bbulkStateCount_getter() != 0:
            return self.bbulkPacketCount_getter() / self.bbulkStateCount_getter()
        return 0.0

    def bAvgBulkRate(self) -> float:
        if self.bbulkDuration_getter() != 0:
            # Rate in bytes per second
            return self.bbulkSizeTotal_getter() / self.bbulkDurationInSecond()
        return 0.0


    # Subflow Feature Getters (read the state variables updated by detectUpdateSubflows)
    def getSflow_fpackets(self) -> float:
        # Average forward packets per subflow state count (Java calculates as total fwd packets / sfCount)
        if self.sfCount <= 0: return 0.0
        return len(self.forward) / self.sfCount

    def getSflow_fbytes(self) -> float:
         # Average forward bytes per subflow state count (Java calculates as total fwd bytes / sfCount)
        if self.sfCount <= 0: return 0.0
        return self.forwardBytes / self.sfCount

    def getSflow_bpackets(self) -> float:
        # Average backward packets per subflow state count (Java calculates as total bwd packets / sfCount)
        if self.sfCount <= 0: return 0.0
        return len(self.backward) / self.sfCount

    def getSflow_bbytes(self) -> float:
        # Average backward bytes per subflow state count (Java calculates as total bwd bytes / sfCount)
        if self.sfCount <= 0: return 0.0
        return self.backwardBytes / self.sfCount


    # Initial Window Bytes Getters
    def getInit_Win_bytes_forward(self) -> int:
        return self.Init_Win_bytes_forward

    def getInit_Win_bytes_backward(self) -> int:
        return self.Init_Win_bytes_backward

    # Active Data Packets Forward Getters
    def getAct_data_pkt_forward(self) -> int:
        return self.Act_data_pkt_forward

    # Minimum Segment Size Forward Getters
    def getMin_seg_size_forward(self) -> float:
         # The Java code initializes with float('inf') and takes the min header size.
         # If no forward packets, this would remain the initial infinity value.
         # The dump method output suggests it should be 0 if no forward packets or min is still infinity.
         # Return 0.0 if self.min_seg_size_forward is still the initial infinity value.
        return self.min_seg_size_forward if self.min_seg_size_forward != float('inf') else 0.0


    # Active Time Getters (read the state variables updated by updateActiveIdleTime)
    def getActiveMean(self) -> float:
        return statistics.mean(self.flowActive) if self.flowActive else 0.0
    def getActiveStd(self) -> float:
        return statistics.stdev(self.flowActive) if len(self.flowActive) > 1 else 0.0
    def getActiveMax(self) -> float:
        return max(self.flowActive) if self.flowActive else 0.0
    def getActiveMin(self) -> float:
        return min(self.flowActive) if self.flowActive else 0.0

    # Idle Time Getters (read the state variables updated by updateActiveIdleTime)
    def getIdleMean(self) -> float:
        return statistics.mean(self.flowIdle) if self.flowIdle else 0.0
    def getIdleStd(self) -> float:
        return statistics.stdev(self.flowIdle) if len(self.flowIdle) > 1 else 0.0
    def getIdleMax(self) -> float:
        return max(self.flowIdle) if self.flowIdle else 0.0
    def getIdleMin(self) -> float:
        return min(self.flowIdle) if self.flowIdle else 0.0

    # Label (Placeholder)
    def getLabel(self) -> str:
        # This would typically be determined from the pcap file's context or a separate label file
        # Replicating the commented-out Java logic for demonstration if needed,
        # otherwise returning the default "NeedManualLabel".
        # Example of conditional labeling (replace with your actual labeling logic)
        # if "147.32.84.165" in (self.getSrc(), self.getDst()):
        #      return "BOTNET"
        # else:
        #      return "BENIGN"
        return "NeedManualLabel"


    def dumpFlowBasedFeaturesEx(self) -> str:
        """
        Generates a comma-separated string of all 85 flow features
        in the exact order specified by the Java dumpFlowBasedFeaturesEx method.
        """
        dump = []
        separator = ","

        # Append features in the order of the Java dump method
        # Using str() to ensure all values are converted to strings
        try:
             dump.append(str(self.getFlowId())) # 1
             dump.append(str(self.getSrc())) # 2
             dump.append(str(self.getSrcPort())) # 3
             dump.append(str(self.getDst())) # 4
             dump.append(str(self.getDstPort())) # 5
             dump.append(str(self.getProtocol())) # 6

             # Format timestamp like Java: "dd/MM/yyyy hh:mm:ss a" (AM/PM)
             # Java's timestampInMicros / 1000L gives milliseconds, then formatted
             timestamp_ms = self.getFlowStartTime() // 1000
             # Convert milliseconds to seconds for Python's fromtimestamp
             # Use a default timestamp if flowStartTime is zero or causes an error
             try:
                  timestamp_sec = timestamp_ms / 1000.0
                  formatted_timestamp = datetime.fromtimestamp(timestamp_sec).strftime("%d/%m/%Y %I:%M:%S %p")
             except (ValueError, OSError) as e:
                  logger.warning(f"Could not format timestamp {timestamp_ms} for flow {self.getFlowId()}: {e}. Using default.")
                  formatted_timestamp = "00/00/0000 12:00:00 AM" # Default or error indicator


             dump.append(formatted_timestamp) # 7


             dump.append(str(self.getFlowDuration())) # 8

             dump.append(str(self.getTotalFwdPackets())) # 9
             dump.append(str(self.getTotalBackwardPackets())) # 10
             dump.append(str(self.getTotalLengthofFwdPackets())) # 11
             dump.append(str(self.getTotalLengthofBwdPackets())) # 12

             # Fwd Packet Length Stats (Max, Min, Mean, Std Dev) - Features 13-16
             if self.getTotalFwdPackets() > 0:
                 dump.append(str(self.getFwdPacketLengthMax()))
                 dump.append(str(self.getFwdPacketLengthMin()))
                 dump.append(str(self.getFwdPacketLengthMean()))
                 dump.append(str(self.getFwdPacketLengthStd()))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros

             # Bwd Packet Length Stats (Max, Min, Mean, Std Dev) - Features 17-20
             if self.getTotalBackwardPackets() > 0:
                 dump.append(str(self.getBwdPacketLengthMax()))
                 dump.append(str(self.getBwdPacketLengthMin()))
                 dump.append(str(self.getBwdPacketLengthMean()))
                 dump.append(str(self.getBwdPacketLengthStd()))
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros


             dump.append(str(self.getFlowBytesPerSec())) # 21
             dump.append(str(self.getFlowPacketsPerSec())) # 22

             dump.append(str(self.getFlowIATMean())) # 23
             dump.append(str(self.getFlowIATStd())) # 24
             dump.append(str(self.getFlowIATMax())) # 25
             dump.append(str(self.getFlowIATMin())) # 26

             # Fwd IAT Stats (Total, Mean, Std Dev, Max, Min) - Features 27-31
             # Note: Java checks forward.size() > 1 for IAT stats
             if len(self.forward) > 1:
                 dump.append(str(self.getFwdIATTotal()))
                 dump.append(str(self.getFwdIATMean()))
                 dump.append(str(self.getFwdIATStd()))
                 dump.append(str(self.getFwdIATMax()))
                 dump.append(str(self.getFwdIATMin()))
             else:
                 dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             # Bwd IAT Stats (Total, Mean, Std Dev, Max, Min) - Features 32-36
             # Note: Java checks backward.size() > 1 for IAT stats
             if len(self.backward) > 1:
                 dump.append(str(self.getBwdIATTotal()))
                 dump.append(str(self.getBwdIATMean()))
                 dump.append(str(self.getBwdIATStd()))
                 dump.append(str(self.getBwdIATMax()))
                 dump.append(str(self.getBwdIATMin()))
             else:
                 dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             dump.append(str(self.getFwdPSHFlags())) # 37
             dump.append(str(self.getBwdPSHFlags())) # 38
             dump.append(str(self.getFwdURGFlags())) # 39
             dump.append(str(self.getBwdURGFlags())) # 40

             dump.append(str(self.getFwdHeaderLength())) # 41
             dump.append(str(self.getBwdHeaderLength())) # 42
             dump.append(str(self.getfPktsPerSecond())) # 43
             dump.append(str(self.getbPktsPerSecond())) # 44

             # Packet Length Stats (Min, Max, Mean, Std Dev, Variance) - Features 45-49
             all_packet_lengths = self.fwdPktStats + self.bwdPktStats
             if all_packet_lengths: # Check if there are any packets with payload
                 dump.append(str(self.getPacketLengthMin()))
                 dump.append(str(self.getPacketLengthMax()))
                 dump.append(str(self.getPacketLengthMean()))
                 dump.append(str(self.getPacketLengthStd()))
                 dump.append(str(self.getPacketLengthVariance()))
             else:
                  dump.extend(["0.0"] * 5) # Use 0.0 for floating point zeros


             # Global Flag Counts (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE) - Features 50-57
             dump.append(str(self.getFINFlagCount())) # 50
             dump.append(str(self.getSYNFlagCount())) # 51
             dump.append(str(self.getRSTFlagCount())) # 52
             dump.append(str(self.getPSHFlagCount())) # 53
             dump.append(str(self.getACKFlagCount())) # 54
             dump.append(str(self.getURGFlagCount())) # 55
             dump.append(str(self.getCWRFlagCount())) # 56
             dump.append(str(self.getECEFlagCount())) # 57

             dump.append(str(self.getDownUpRatio())) # 58
             dump.append(str(self.getAveragePacketSize())) # 59
             dump.append(str(self.fAvgSegmentSize())) # 60
             dump.append(str(self.bAvgSegmentSize())) # 61
             # Feature 62 is a duplicate of 41 (Fwd Header Length) based on the comment in FlowFeature.java,
             # but the dump method explicitly includes it. Replicating the dump order.
             dump.append(str(self.getFwdHeaderLength())) # 62 (Duplicate)


             # Bulk Features (Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate,
             #               Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate) - Features 63-68
             dump.append(str(self.fAvgBytesPerBulk())) # 63
             dump.append(str(self.fAvgPacketsPerBulk())) # 64
             dump.append(str(self.fAvgBulkRate())) # 65
             dump.append(str(self.bAvgBytesPerBulk())) # 66
             dump.append(str(self.bAvgPacketsPerBulk())) # 67
             dump.append(str(self.bAvgBulkRate())) # 68

             # Subflow Features (Fwd Packets, Fwd Bytes, Bwd Packets, Bwd Bytes) - Features 69-72
             # Note: These are average packets/bytes *per subflow state count* based on the Java getters.
             dump.append(str(self.getSflow_fpackets())) # 69
             dump.append(str(self.getSflow_fbytes())) # 70
             dump.append(str(self.getSflow_bpackets())) # 71
             dump.append(str(self.getSflow_bbytes())) # 72

             dump.append(str(self.getInit_Win_bytes_forward())) # 73
             dump.append(str(self.getInit_Win_bytes_backward())) # 74
             dump.append(str(self.getAct_data_pkt_forward())) # 75
             dump.append(str(self.getMin_seg_size_forward())) # 76

             # Active Time Stats (Mean, Std Dev, Max, Min) - Features 77-80
             if self.flowActive: # Check if there are any active periods recorded
                 dump.append(str(self.getActiveMean())) # 77
                 dump.append(str(self.getActiveStd())) # 78
                 dump.append(str(self.getActiveMax())) # 79
                 dump.append(str(self.getActiveMin())) # 80
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros

             # Idle Time Stats (Mean, Std Dev, Max, Min) - Features 81-84
             if self.flowIdle: # Check if there are any idle periods recorded
                 dump.append(str(self.getIdleMean())) # 81
                 dump.append(str(self.getIdleStd())) # 82
                 dump.append(str(self.getIdleMax())) # 83
                 dump.append(str(self.getIdleMin())) # 84
             else:
                 dump.extend(["0.0"] * 4) # Use 0.0 for floating point zeros


             dump.append(str(self.getLabel())) # 85 (Last feature)

        except Exception as e:
             # Log error during dump, but try to produce a line with error indicator
             logger.error(f"Error during dumpFlowBasedFeaturesEx for flow {getattr(self, 'flowId', 'UnknownID')} (object id: {id(self)}): {e}")
             # Fill the rest of the features with "ERROR" to maintain column count
             while len(dump) < 85:
                 dump.append("ERROR")


        return separator.join(dump)


# --- Flow Generator Logic (based on FlowGenerator.java) ---
import csv
from scapy.all import rdpcap
from scapy.packet import Packet

class FlowGenerator:
    def __init__(self, bidirectional: bool, flow_timeout_micros: int, activity_timeout_micros: int):
        self.bidirectional = bidirectional
        self.flow_timeout_micros = flow_timeout_micros
        self.activity_timeout_micros = activity_timeout_micros
        self.current_flows = {}  # Dictionary to store active flows: flow_id -> BasicFlow object
        self.finished_flows = [] # List to store completed flows
        self.finished_flow_count = 0 # To mimic the Java counter
        logger.debug("FlowGenerator initialized.")


    def addPacket(self, packet: Packet):
        # Create BasicPacketInfo first, filtering non-IP/IPv6 packets
        try:
            packet_info = BasicPacketInfo(packet)
        except ValueError:
             # logger.debug("Skipping non-IP/IPv6 packet") # Too noisy
             return # Skip this packet if it's not IP/IPv6
        except Exception as e:
             logger.error(f"Error creating BasicPacketInfo for packet from scapy: {e}")
             return # Skip this packet if BasicPacketInfo creation failed

        current_timestamp = packet_info.getTimeStamp()
        logger.debug(f"Processing packet id {packet_info.id}, timestamp {current_timestamp}")


        # Check for expired flows (active timeout) before processing the new packet
        # Make a copy of keys to avoid modifying the dict during iteration
        keys_to_check = list(self.current_flows.keys())
        logger.debug(f"Checking {len(keys_to_check)} current flows for timeouts.")
        for flow_id in keys_to_check:
            flow = self.current_flows[flow_id]
            # Active Timeout: time since the *start* of the flow exceeds the flow timeout
            if (current_timestamp - flow.getFlowStartTime()) > self.flow_timeout_micros:
                 logger.debug(f"Flow {flow_id} timed out.")
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
            flow = self.current_flows.get(flow_id) # Use .get() for safer retrieval

            if flow is None:
                 # This case should ideally not happen if flow_id was found in keys_to_check,
                 # but including a check as a safeguard.
                 logger.error(f"Flow {flow_id} unexpectedly not found in current_flows after lookup for packet {packet_info.id}!")
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
                     is_forward = packet_info.isForwardPacket(flow.getSrc()) # This relies on flow.getSrc() being valid
                     if is_forward:
                          flow.setFwdFINFlags()
                          logger.debug(f"Packet {packet_info.id} is FWD FIN. Flow {flow_id} FWD FIN count: {flow.getFwdFINFlags()}")
                     else:
                          flow.setBwdFINFlags()
                          logger.debug(f"Packet {packet_info.id} is BWD FIN. Flow {flow_id} BWD FIN count: {flow.getBwdFINFlags()}")


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
                          logger.error(f"Error adding terminating packet {packet_info.id} to flow {flow_id}: {e}")
                          # Still attempt to close the flow even if adding the last packet failed
                     self._close_flow(flow_id, current_timestamp, "FIN/RST Flag")
                     return # Flow closed, processing for this packet is done


            # If not terminated by timeouts, FIN, or RST, add the packet to the existing flow
            try:
                 flow.addPacket(packet_info)
                 logger.debug(f"Successfully added packet {packet_info.id} to existing flow {flow_id}.")
                 # self.current_flows[flow_id] = flow # Ensure the updated flow is in the map (redundant but harmless)
            except Exception as e:
                 logger.error(f"Error adding packet {packet_info.id} to existing flow {flow_id}: {e}")
                 # Do not remove the flow on error, might recover or be closed by timeout later.
                 # Consider incrementing a flow-specific error counter if needed.


        else:
            # New flow detected
            logger.debug(f"Packet {packet_info.id} is starting a new flow.")
            # Create a new BasicFlow instance
            try:
                 # Use the constructor that takes the first packet.
                 # This constructor is now responsible for setting the flow's identity.
                 # No need to pass flowSrc, flowDst etc. here for NEW flows.
                 new_flow = BasicFlow(self.bidirectional, packet_info, activityTimeout=self.activity_timeout_micros)

                 # Add the new flow to the dictionary using its determined flowId
                 flow_id_for_dict = new_flow.getFlowId()

                 # Safeguard: Should not exist if this path is truly for new flows
                 if flow_id_for_dict in self.current_flows:
                      logger.warning(f"New flow creation for packet {packet_info.id} attempted to overwrite existing flow key {flow_id_for_dict}. This suggests a logic error.")
                      # Decide how to handle: keep old flow? Overwrite? For now, overwrite like the Java map behavior.

                 self.current_flows[flow_id_for_dict] = new_flow
                 logger.debug(f"Created new flow {flow_id_for_dict} (object id: {id(new_flow)}) for packet {packet_info.id}")

            except Exception as e:
                 # This catch block seems to be where the 'checkFlags' error is reported
                 logger.error(f"Error creating new flow for packet {packet_info.id}: {e}")
                 # Discard the packet if new flow creation failed and log the error.
                 # The packet was already counted in total_scapy_packets, and will be part of discarded_packet_count.


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
                     logger.error(f"Error finalizing flow {flow_id} (object id: {id(flow)}) before closing: {e}")
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
        logger.debug(f"Closing all remaining {len(keys_to_check)} flows at end of PCAP processing.")
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
                         logger.error(f"Error dumping finished flow {getattr(flow, 'flowId', 'UnknownID')} (object id: {id(flow)}) to CSV: {e}")

                # Dump remaining current flows (those not terminated by timeouts or flags during processing)
                # These flows also need to have packetCount() > 1 to be dumped.
                # Their features are finalized when dumpFlowBasedFeaturesEx is called.
                current_flows_to_dump = [flow for flow in self.current_flows.values() if flow and flow.packetCount() > 1] # Added check for flow being None
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
                         logger.error(f"Error dumping current flow {getattr(flow, 'flowId', 'UnknownID')} (object id: {id(flow)}) to CSV: {e}")


            logger.info("Successfully dumped %d flows to %s", total_dumped, output_filepath)
            return total_dumped
        except IOError as e:
            logger.error("Error writing to CSV file %s: %s", output_filepath, e)
            return 0


# --- Main execution logic ---

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
    except OSError as e:
        logger.error("Error listing files in directory %s: %s", pcap_path, e)
        sys.exit(1)


    if not pcap_files:
        logger.info("Sorry, no pcap files can be found under: %s", pcap_path)
        return

    logger.info("")
    logger.info("PythonFlowMeter found: %d Files.", len(pcap_files))

    total_flows_dumped = 0 # Renamed from total_flows_generated to reflect what is dumped

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
        discarded_packet_count = 0

        start_time_script_sec = time.time() # For script duration timing in seconds


        try:
            # Use rdpcap to read packets from the file
            packets = rdpcap(filepath)
            total_scapy_packets = len(packets)
            logger.info(f"Read {total_scapy_packets} packets from {file}")

            # Iterate through packets and add to flow generator
            for i, packet in enumerate(packets):
                try:
                    # addPacket handles BasicPacketInfo creation and IP/IPv6 filtering internally
                    flow_gen.addPacket(packet)

                    # Track first/last timestamp of packets *read by scapy*
                    # This might include non-IP/IPv6 packets, mirroring the Java PacketReader's overall tracking
                    packet_timestamp_micros = int(packet.time * 1_000_000)
                    if first_packet_timestamp_micros is None or packet_timestamp_micros < first_packet_timestamp_micros:
                         first_packet_timestamp_micros = packet_timestamp_micros
                    if last_packet_timestamp_micros is None or packet_timestamp_micros > last_packet_timestamp_micros:
                         last_packet_timestamp_micros = packet_timestamp_micros

                except Exception as e:
                     # addPacket is already trying to catch errors during BasicPacketInfo creation and adding to flow.
                     # If an exception reaches here, it's likely an unhandled one from within addPacket or flow logic.
                     logger.error(f"Unhandled error processing packet {i+1}/{total_scapy_packets}: {e}")
                     discarded_packet_count += 1


            # Close any remaining active flows at the end of the file
            # Use the timestamp of the last packet read by scapy if available, otherwise current time.
            final_closing_timestamp = last_packet_timestamp_micros if last_packet_timestamp_micros is not None else int(time.time() * 1_000_000)
            logger.debug(f"Calling close_all_flows with final timestamp {final_closing_timestamp}")
            flow_gen.close_all_flows(final_closing_timestamp)


        except FileNotFoundError:
            logger.error("PCAP file not found: %s", filepath)
            continue
        except Exception as e:
            logger.error("Error processing PCAP file %s: %s", filepath, e)
            continue


        end_time_script_sec = time.time()
        logger.info("Done! in %.2f seconds", (end_time_script_sec - start_time_script_sec))
        logger.info("\t Total packets read by scapy: %d", total_scapy_packets)
        # The counting of "Packets passed to FlowGenerator.addPacket" vs "Ignored" is tricky
        # with the try/except inside addPacket. Let's simplify the logging here.
        # Total packets - discarded includes packets skipped in BasicPacketInfo + packets causing errors in addPacket/flow logic.
        logger.info("\t Packets processed by FlowGenerator (BasicPacketInfo created successfully): %d", total_scapy_packets - discarded_packet_count)
        logger.info("\t Packets causing unhandled errors during iteration: %d", discarded_packet_count)


        if first_packet_timestamp_micros is not None and last_packet_timestamp_micros is not None:
             # Convert microseconds duration to seconds for logging
             pcap_duration_micros = last_packet_timestamp_micros - first_packet_timestamp_micros
             logger.info("PCAP duration %.6f seconds", pcap_duration_micros / 1_000_000.0)
        else:
             logger.info("PCAP duration: N/A (no packets read or processed)")

        logger.info("----------------------------------------------------------------------------")

        # Dump flows to CSV
        csv_filename = file.replace(".pcap", "") + "_PythonFeatures.csv" # Naming convention
        total_flows_dumped += flow_gen.dump_labeled_flow_based_features(out_path, csv_filename, FlowFeature.get_header())

    logger.info("\n\n----------------------------------------------------------------------------")
    # The Java code reports total flows from finishedFlows + currentFlows *before* dumping.
    # This Python version reports the total number of flows actually dumped to CSV (packetCount() > 1).
    logger.info("TOTAL FLOWS DUMPED (packet count > 1): %d", total_flows_dumped)
    logger.info("----------------------------------------------------------------------------\n")

if __name__ == "__main__":
    main()