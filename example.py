# -*- coding: utf8 -*-

import socket
import os
import sys
import threading
import Queue
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

                    if (dtap.protocol_discriminator == 0x09) and (dtap.dtap_sms_type == 0x01) and (dtap.cp_lenth > 2) \
                            and len(reassembled_segments) > 8:
                        rp = RP(dtap.next_data)

                        # Message Type RP-DATA (Network to MS)
                        if rp.RP_message_type == 1:
                            tpdu = TPDU(rp.next_data)
                            print "-" * 90
                            # SMS-DELIVER
                            if tpdu.TP_mti == 0x00:
                                print("%s (Downlink) [ From %s] %s" % (
                                            tpdu.get_sms_time(), tpdu.TP_origin, tpdu.get_sms_text()))

                            # SMS-STATUS REPORT
                            if tpdu.TP_mti == 0x02:
                                print(
                                    "%s (Downlink) [ From %s] SMS status report " % (tpdu.get_sms_time(), tpdu.TP_origin))
                        
                        # Message Type RP-DATA (MS to Network)
                        elif rp.RP_message_type == 0:
                            tpdu = TPDU(rp.next_data)
                            print "-" * 90
                            center_time = time.localtime()
                            # SMS-SUBMIT
                            if tpdu.TP_mti == 0x01:
                                print("%s (Uplink) [ From %s] %s" % (
                                            tpdu.get_sms_time(), tpdu.TP_dest, tpdu.get_sms_text()))

                        # RP-ACK
                        elif rp.RP_message_type == 2:
                            # SMS-DELIVER REPORT
                            print "-" * 90
                            print("%s (Uplink) SMS status report" %
                                  tpdu.get_sms_time())


if __name__ == '__main__':
    print "Start listen port 4729..."
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