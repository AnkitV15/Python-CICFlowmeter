# packet_info.py

from scapy.all import Packet, IP, IPv6, TCP, UDP, Raw
import logging

logger = logging.getLogger(__name__) # Get logger for this module

# --- Basic Packet Information Class (based on BasicPacketInfo.java) ---
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