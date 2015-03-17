#!/usr/bin/python

import socket
import os
import sys
import threading
import Queue
import time
import hexdump
import subprocess
from sms import *


def handle_message(**kargs):
    gsm_sms_segs = ""
    while True:
        data = kargs['messages'].get(True)
        gsmtap = GSMTAP(data)
        lapdm = LAPDm(gsmtap.next_data)
        # TS 04.06, 3.3.3, SAPI: 3 - Short message service && frame type is 0x00
        if (gsmtap.channel_type == 8) and (lapdm.sapi == 3) and (lapdm.frame_type == 0x00):
            if lapdm.last_segment==0:
                hexdump.hexdump(lapdm.next_data)
                dtap=DTAP(lapdm.next_data)
                rp=RP(dtap.next_data)
                print ord(data[20:21])& 0x0F
                #print rp.RP_origin
                # print("[SMS from %s] %s" % (tpdu.TP_origin, tpdu.get_data()))     
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
