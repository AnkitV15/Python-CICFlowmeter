# flow_feature.py

import enum
import statistics
from datetime import datetime
import logging

logger = logging.getLogger(__name__) # Get logger for this module

# --- Flow Feature Enum (based on FlowFeature.java) ---
class FlowFeature(enum.Enum):
    # Full list of 85 features as per FlowFeature.java
    # The order here defines the output column order
    # (Feature Name, Abbreviation, Is_Numeric)
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
    idl_min = ("Idle Min", "IlMI", True) # Corrected abbreviation based on Java dump # Corrected abbreviation based on Java dump
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