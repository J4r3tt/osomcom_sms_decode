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
        self.length = ord(lapdm[2]) >> 2
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
        self.RP_origin_len = ord(rp[2])
        self.RP_origin_ext = ord(rp[3])
        self.RP_origin = bcdDigits(rp[4:3 + self.RP_origin_len])
        self.RP_dest_start = 3 + self.RP_origin_len
        self.RP_dest_len = ord(rp[self.RP_dest_start])
        self.RP_dest_over = self.RP_dest_start + self.RP_dest_len + 1
        self.length = ord(rp[self.RP_dest_over])
        self.tpdu_off = self.RP_dest_over + 1
        self.next_data = self.rp[self.tpdu_off:self.tpdu_off + self.length]
    # def get_tpdu(self):
    #     return self.rp[self.tpdu_off:self.tpdu_off+self.length]


class TPDU:

    def __init__(self, tpdu):
        self.TP_udhi = (ord(tpdu[0]) >> 6) & 0x01
        self.TP_mms = (ord(tpdu[0]) >> 2) & 0x01
        self.TP_mti = ord(tpdu[0]) & 0x03
        # SMS-DELIVER or SMS-SUBMIT
        if (self.TP_mti == 0) or (self.TP_mti == 1):
            self.TP_origin_num = ord(tpdu[1])
            self.TP_origin_len = (
                self.TP_origin_num >> 1) + (self.TP_origin_num % 2)
            self.TP_origin_ext = ord(tpdu[2])
            self.TP_origin = bcdDigits(tpdu[3:3 + self.TP_origin_len])
            self.TP_charaterset = ord(
                tpdu[3 + self.TP_origin_len + 1]) >> 2 & 0x03
            self.data_start = 3 + self.TP_origin_len + 9
            self.tpu_len = ord(tpdu[self.data_start])
            if self.TP_udhi == 0:
                self.data = tpdu[
                    self.data_start + 1:self.data_start + 1 + self.tpu_len]
            else:
                self.userdata_len = ord(tpdu[self.data_start + 1])
                self.data = tpdu[
                    self.data_start + 2 + self.userdata_len:self.data_start + 2 + self.userdata_len + self.tpu_len]
        # SMS-STATUS REPORT
        elif self.TP_mti == 2:
            self.TP_origin_num = ord(tpdu[2])
            self.TP_origin_len = (
                self.TP_origin_num >> 1) + (self.TP_origin_num % 2)
            self.TP_origin_ext = ord(tpdu[3])
            self.TP_origin = bcdDigits(tpdu[4:4 + self.TP_origin_len])
            self.status_result = ord(tpdu[4 + self.TP_origin_len + 14:]) & 0x7f
