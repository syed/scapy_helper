#!/usr/bin/python 

from scapy.all import *
from  scapy_helper  import ScapyConnection 
from scapy_helper import SA
import time

http_req = 'GET /index.html HTTP/1.1\r\nHost: 1.1.1.1\r\nAccept: */*\r\n\r\n'
class TestScapy(ScapyConnection):
    def __init__(self) :
        ScapyConnection.__init__(self,src="10.103.4.27" , dst="10.102.34.227" , sport=5001 ,dport=80)
        self.a_ack = 0 

    def process_packet(self,p):
        p = p[TCP]
        #p.show()
        if p.flags == SA :
            self.curr_ack = self.irs = p.seq + 1
            #send ack back
            print "Sending ACK"
            ack = self.create_packet(flags='A')
            self.send_packet(ack , 0)
            time.sleep(2)
            #send data
            print "Sending data"
            data = self.create_packet(data=http_req)
            self.send_packet(data,0.5) 
            self.curr_seq += len(http_req)
        else : 
            try :
                if len(p.load)>0 :
                    self.curr_ack = p.seq+len(p.load)

                if p.load== 'a' :
                    #ack this 
                    ack = self.create_packet()
                    self.send_packet(ack , 0.2 )
                    if self.a_ack == 0 :
                        print "A ack " + str(self.curr_ack)
                        self.a_ack = self.curr_ack #for dup ack

                elif p.load == 'b' or p.load == 'c' or p.load == 'd' :
                    print "sending with ack" + str(self.a_ack)
                    dup_ack = self.create_packet(ack=self.a_ack)
                    print "got data"
                    print p.load
                    self.send_packet(dup_ack , 0.2)

                else : #other packet , just ack it 
                    ack = self.create_packet()
                    self.send_packet(ack , 0.2)
            except : 
                pass


if __name__ == "__main__" :
    t = TestScapy()
    t.start(type='client')


