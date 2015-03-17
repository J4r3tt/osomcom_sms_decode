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
        if gsmtap.version==2:
            lapdm = LAPDm(gsmtap.next_data)
            # SAPI: 3 - Short message service && frame type is 0x00
            if (gsmtap.channel_type == 8) and (lapdm.sapi == 3) and (lapdm.frame_type == 0x00):
                sms_segments+=lapdm.next_data
                if lapdm.last_segment==0:
                    reassembled_segments=sms_segments
                    sms_segments=""
                    dtap=DTAP(reassembled_segments)
                    if (dtap.protocol_discriminator==0x09) and (dtap.dtap_sms_type==0x01) and (dtap.cp_lenth>0x10) and len(reassembled_segments)>10:


                    #hexdump.hexdump(lapdm.next_data)
                        rp=RP(dtap.next_data)
                        tpdu=TPDU(rp.next_data)
                #print rp.RP_origin
                print("[SMS from %s] %s" % (tpdu.TP_origin, tpdu.get_data()))     
                # print("LINK[%d] ARFCN=%d TIME_SLOT=%d CHANNEL=%d, N(R)=%d N(S)=%d, segment more[%d], payload len=%d\n" %
                #   (gsmtap.link, gsmtap.arfcn, gsmtap.time_slot, gsmtap.channel_type, lapdm.n_r, lapdm.n_s, lapdm.last_segment, lapdm.length))

if __name__ == '__main__':
    print "Sniffer Start..."
    print "Press Ctrl+C to Exit."
    try:
        q = Queue.Queue()
        t = threading.Thread(
            target=handle_message, name="handle_message_thread", kwargs={'messages': q})
        t.daemon = True
        t.start()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', 4729))
        while True:
            udp_data, addr = s.recvfrom(2048)
            q.put(udp_data)
        s.close()
    except KeyboardInterrupt:
        try:
            exit()
        except:
            pass
