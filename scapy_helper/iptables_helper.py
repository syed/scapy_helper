#!/usr/bin/python 

import os 

def do_iptables(dst='10.102.34.123',dport=80):
	cmd1 = 'iptables -A OUTPUT -d ' + dst  + ' -p ICMP --icmp-type port-unreachable -j DROP'
	cmd2 = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' +  dst + ' --dport ' + str(dport) + ' -j DROP'
	os.system(cmd1)
	os.system(cmd2)

def clean_iptables():
	os.system('iptables -F OUTPUT')



