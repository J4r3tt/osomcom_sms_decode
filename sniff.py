#!/usr/bin/python

import socket
import os
import sys
import threading
import Queue
import time
import subprocess
from sms import *


def handle_message(**kargs):
    sms_segments = ""
    while True:
        data = kargs['messages'].get(True)
        gsmtap = GSMTAP(data)
        if gsmtap.version == 2:
            lapdm = LAPDm(gsmtap.next_data)
            # sapi is 3-sms && frame type is 0x00
            if (gsmtap.channel_type == 8) and (lapdm.sapi == 3) and (lapdm.frame_type == 0x00):
                # put the packets together
                sms_segments += lapdm.next_data
                # if last packet
                if lapdm.last_segment == 0:
                    # ready to handle this segment
                    reassembled_segments = sms_segments
                    sms_segments = ""
                    dtap = DTAP(reassembled_segments)
                    if (dtap.protocol_discriminator == 0x09) and (dtap.dtap_sms_type == 0x01) and (dtap.cp_lenth > 0x10) \
                            and len(reassembled_segments) > 10:
                        # hexdump.hexdump(lapdm.next_data)
                        rp = RP(dtap.next_data)
                        # dowanlink
                        if rp.RP_message_type == 0x01:
                            tpdu = TPDU(rp.next_data)
                            # SMS-DELIVER
                            print tpdu.TP_mti
                            if tpdu.TP_mti == 0x00:
                                # print rp.RP_origin
                                print("[SMS from %s] %s" % (
                                    tpdu.TP_origin, tpdu.data.decode("utf-16be").encode("utf-8")))
                            if tpdu.TP_mti == 0x02:
                                print("Downlink SMS status report")
                        else:
                            print ("Uplink SMS status report ")
                # print("LINK[%d] ARFCN=%d TIME_SLOT=%d CHANNEL=%d, N(R)=%d N(S)=%d, segment more[%d], payload len=%d\n" %
                #   (gsmtap.link, gsmtap.arfcn, gsmtap.time_slot, gsmtap.channel_type, lapdm.n_r, lapdm.n_s, lapdm.last_segment, lapdm.length))

if __name__ == '__main__':
    print "Sniffer Start..."
    print "Press Ctrl+C to Exit."
    try:
        q=Queue.Queue()
        t=threading.Thread(
            target=handle_message, name="handle_message_thread", kwargs={'messages': q})
        t.daemon=True
        t.start()
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', 4729))
        while True:
            udp_data, addr=s.recvfrom(2048)
            q.put(udp_data)
        s.close()
    except KeyboardInterrupt:
        try:
            exit()
        except:
            pass
