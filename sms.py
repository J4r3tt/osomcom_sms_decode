# -*- coding: utf-8 -*-
# base on wireshark gsmtap decode
from struct import *


def bcdDigits(chars):
    result = []
    for char in chars:
        lo = ord(char) & 0xF
        hi = ord(char) >> 4

        result.append(lo)
        if (hi == 0xF):
            break
        result.append(hi)
    return "".join([str(v) for v in result])



class GSMTAP:
    # gsmtap http://bb.osmocom.org/trac/attachment/wiki/GSMTAP/gsmtap.h

    def __init__(self, gsmtap):
        self.gsmtap = gsmtap
        self.version = ord(gsmtap[0])
        self.hdr_len = ord(gsmtap[1]) << 2
        self.payload_type = ord(gsmtap[2])
        self.time_slot = ord(gsmtap[3])
        self.arfcn = (ord(gsmtap[4]) & 0x3F) * 0x100 + ord(gsmtap[5])
        self.link = ord(gsmtap[4]) >> 6
        self.signal_noise = ord(gsmtap[6])
        self.signal_level = ord(gsmtap[7])

        # GSM Frame Number
        self.channel_type = ord(gsmtap[12])
        self.antenna_number = ord(gsmtap[13])
        self.sub_slot = ord(gsmtap[14])
        self.next_data = self.gsmtap[self.hdr_len:]

    # def get_payload(self):
        # return self.gsmtap[self.hdr_len:]
        # return self.gsmtap[self.hdr_len:]


class LAPDm:
    # base on wireshark gsmtap decode

    def __init__(self, lapdm):
        self.lapdm = lapdm
        self.addr_field = ord(lapdm[0])
        self.lpd = (ord(lapdm[0]) >> 5) & 0x3
        self.sapi = (ord(lapdm[0]) >> 2) & 0x7
        self.ctrl_field = ord(lapdm[1])
        self.n_r = ord(lapdm[1]) >> 5
        self.n_s = (ord(lapdm[1]) >> 1) & 0x7
        self.frame_type = ord(lapdm[1]) & 0x1
        self.len_field = ord(lapdm[2])
        self.last_segment = (ord(lapdm[2]) >> 1) & 0x1
        self.length = (ord(lapdm[2]) >> 2) & 0x3f
        self.next_data = self.lapdm[3:]
    # def get_data(self):
        # return self.lapdm[3:]


class DTAP:

    def __init__(self, dtap):
        self.dtap = dtap
        self.protocol_discriminator = ord(dtap[0:1]) & 0xF
        self.dtap_sms_type = ord(dtap[1])
        self.cp_lenth = ord(dtap[2])
        self.next_data = dtap[3:]


class RP:

    def __init__(self, rp):
        self.rp = rp
        self.RP_message_type = ord(rp[0])

        # Message Type RP-DATA (Network to MS)
        if self.RP_message_type == 0x01:
            self.RP_origin_len = ord(rp[2])
            self.RP_origin_ext = ord(rp[3])
            self.RP_origin = bcdDigits(rp[4:3 + self.RP_origin_len])
            self.length = ord(rp[3 + self.RP_origin_len + 1])
            self.next_data = self.rp[3 + self.RP_origin_len + 2:]
        # Message Type RP-DATA (MS to Network)
        elif self.RP_message_type == 0x00:
            self.RP_dest_len = ord(rp[3])
            self.RP_dest_ext = ord(rp[4])
            self.RP_dest = bcdDigits(rp[5:4 + self.RP_dest_len])
            self.lenth = ord(rp[4 + self.RP_dest_len])
            self.next_data = self.rp[4 + self.RP_dest_len + 1:]
       # Message Type RP-ACK (MS to Network)
        elif self.RP_message_type == 0x02:
            self.lenth = ord(rp[3])
            self.next_data = self.rp[4:4 + self.lenth]


class TPDU:

    def __init__(self, tpdu):
        self.TP_udhi = (ord(tpdu[0]) >> 6) & 0x01
        self.TP_mti = ord(tpdu[0]) & 0x03
        # SMS-DELIVER
        if self.TP_mti == 0:
            self.TP_mms = (ord(tpdu[0]) >> 2) & 0x01
            self.TP_origin_num = ord(tpdu[1])
            self.TP_origin_len = (
                self.TP_origin_num >> 1) + (self.TP_origin_num % 2)
            self.TP_origin_ext = ord(tpdu[2])
            self.TP_origin = bcdDigits(tpdu[3:3 + self.TP_origin_len])
            self.TP_charaterset = ord(
                tpdu[3 + self.TP_origin_len + 1]) >> 2 & 0x03
            self.time_stamp = bcdDigits(
                tpdu[3 + self.TP_origin_len + 2:3 + self.TP_origin_len + 8])
            self.data_start = 3 + self.TP_origin_len + 9
            self.tpu_len = ord(tpdu[self.data_start])
            #deal with long sms
            if self.TP_udhi == 0:
                self.data = tpdu[
                    self.data_start + 1:self.data_start + 1 + self.tpu_len]
            else:
                self.userdata_len = ord(tpdu[self.data_start + 1])
                self.data = tpdu[
                    self.data_start + 2 + self.userdata_len:self.data_start + 1 + self.tpu_len]
                    
        # SMS-SUBMIT
        elif self.TP_mti == 1:
            self.TP_vpf=(ord(tpdu[0]) >> 3) & 0x03
            self.TP_dest_num = ord(tpdu[2])
            self.TP_dest_len = (
                self.TP_dest_num >> 1) + (self.TP_dest_num % 2)
            self.TP_dest_ext = ord(tpdu[3])
            self.TP_dest = bcdDigits(tpdu[4:4 + self.TP_dest_len])
            self.TP_charaterset = ord(
                tpdu[4 + self.TP_dest_len + 1]) >> 2 & 0x03
            #if contain TP-Validity-Period header
            if self.TP_vpf==2:
                self.data_start = 4 + self.TP_dest_len + 3
            else:
                self.data_start = 4 + self.TP_dest_len + 2
            self.tpu_len = ord(tpdu[self.data_start])
            #deal with long sms
            if self.TP_udhi == 0:
                self.data = tpdu[
                    self.data_start + 1:self.data_start + 1 + self.tpu_len]
            else:
                self.userdata_len = ord(tpdu[self.data_start + 1])
                self.data = tpdu[
                    self.data_start + 2 + self.userdata_len:self.data_start + 1 + self.tpu_len]

        # SMS-STATUS REPORT
        elif self.TP_mti == 2:
            self.TP_origin_num = ord(tpdu[2])
            self.TP_origin_len = (
                self.TP_origin_num >> 1) + (self.TP_origin_num % 2)
            self.TP_origin_ext = ord(tpdu[3])
            self.TP_origin = bcdDigits(tpdu[4:4 + self.TP_origin_len])
            self.time_stamp = bcdDigits(
                tpdu[4 + self.TP_origin_len:4 + self.TP_origin_len + 6])
            self.status_result = ord(tpdu[4 + self.TP_origin_len + 6]) & 0x7f
