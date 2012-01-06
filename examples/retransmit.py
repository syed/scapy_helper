#!/usr/bin/python 

from scapy.all import *
from  scapy_helper  import ScapyConnection 
from scapy_helper import SA
import time

http_req = 'GET /syed/test.php HTTP/1.1\r\nHost: 1.1.1.1\r\nAccept: */*\r\n\r\n'
http_req2 = 'GET /syed/test.php HTTP/1.1\r\nHost: 2.2.2.2\r\nAccept: */*\r\n\r\n'
class TestScapy(ScapyConnection):
    def __init__(self) :
        ScapyConnection.__init__(self,src="10.103.5.22" , dst="10.102.34.226" , sport=5003 ,dport=80)
        self.a_ack = 0 
        self.req2_sent=0

    def process_packet(self,p):
        p = p[TCP]
        #p.show()
        if p.flags == SA :
            self.curr_ack = self.irs = p.seq + 1
            #send ack back
            print "Got Syn ack Sending ACK"
            ack = self.create_packet(flags='A')
            self.send_packet(ack , 0)
            time.sleep(2)
            #send data
            print "Sending Request data"
            data = self.create_packet(data=http_req)
            self.send_packet(data,0.2) 
            self.curr_seq += len(http_req)
            print "Sending 2nd request"
            data = self.create_packet(data=http_req2)
            self.send_packet(data,0.5) 
            self.old_seq = self.curr_seq
            self.curr_seq += len(http_req)


if __name__ == "__main__" :
    t = TestScapy()
    t.start(type='client')


