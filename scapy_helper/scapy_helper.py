#!/usr/bin/python 

from scapy.all import * 
import time
from multiprocessing import Process
import iptables_helper


#flags 
F=1
S=2
A=16

SA = (S|A)
FA = (F|A)

def do_iptables(dst='192.168.1.1',dport=80):
	cmd1 = 'iptables -A OUTPUT -d ' + dst  + ' -p ICMP --icmp-type port-unreachable -j DROP'
	cmd2 = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' +  dst + ' --dport ' + str(dport) + ' -j DROP'
	os.system(cmd1)
	os.system(cmd2)

def clean_iptables():
	os.system('iptables -F OUTPUT')


class ScapyConnection() :
	""" 
	Main class for scapy connection
	gives functions to create,send and recieve packets
	"""
        def __init__(self,iface='eth0' , src='192.168.1.1' , dst='192.168.1.2' , sport=5000 , 
				dport=81 , iss=100 , mss=128, win=1280,
				bpf_filter=None):
		self.iface =iface

		self.src=src
		self.dst=dst

		self.sport=sport
		self.dport=dport

		if bpf_filter is None :
			bpf_filter='tcp port ' + str(dport) + ' and src ' + dst

		self.bpf_filter = bpf_filter

		self.iss=iss
		self.mss=mss
		self.win=win

		self.curr_seq=iss

		# should be filled when synack comes 
		self.irs = 0
		self.curr_ack=0


	def send_packet(self,pkt,delay=None) :
		p = Process(target=self._scapy_send,args=(pkt,delay))
		p.start()
		#p.join()
		
	def create_packet(self,flags=None,data=None,seq=None,win=None,ack=None) :
		if not flags :
			flags='A'
		if not seq :
			seq = self.curr_seq
		if not ack :
			ack = self.curr_ack
		if not win :
			window = self.win


		if flags == 'S' :
			pkt=IP(dst=self.dst,src=self.src)/TCP(dport=self.dport,sport=self.sport,flags='S',options=[('MSS' , self.mss)],window=window,seq=seq)
			return pkt

		if data :
			return IP(dst=self.dst,src=self.src)/TCP(dport=self.dport,sport=self.sport,flags=flags,ack=ack,seq=seq,window=window)/data
		else :
			return IP(dst=self.dst,src=self.src)/TCP(dport=self.dport,sport=self.sport,flags=flags,ack=ack,seq=seq,window=window)
		

	#this should be inherited by derived class
	def process_packet(self, p ) : 
		p.show()
		

	def start(self,type="client"):
		
		iptables_helper.do_iptables(self.dst,self.dport)

		if type=='client' :
			#send syn 
			p = self.create_packet(flags='S')
			self.send_packet(p,5)
                        self.curr_seq+=1

		#starts the main loop , all captured packets  go to process_packet
		sniff( iface=self.iface , filter=self.bpf_filter ,prn=self.process_packet )
        def _scapy_send(self,pkt,delay):
        	if  delay :
        		time.sleep(delay)
	        #pkt.show()	
	        send(pkt)


	def __del__(self):
		iptables_helper.clean_iptables()
