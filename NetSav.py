# Authors: Shir, Hodaya and Alexey
# Version: 1.0
# Date: 07/2019

# libraries
import argparse
import os
import subprocess
import re
import sys
import signal
from threading import Lock
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

# Global variables
global ssid_list
global s

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
    print(BOLD + "|NetSav v1.0                                                                                 |" + ENDC)
    print(BOLD + "|Coded by Alexey, Hodaya & Shir                                                              |" + ENDC)
    print(BOLD + "+--------------------------------------------------------------------------------------------+\n" + ENDC)

# Function to handle Crtl+C
def signal_handler(signal, frame):
    print(RED + '\n=====================' + ENDC)
    print(RED + '[-] Execution aborted' + ENDC)
    print(RED + '=====================' + ENDC)
    os.system("kill -9 " + str(os.getpid()))
    sys.exit(1)

# Function of signal exit
def signal_exit(signal, frame):
    print "Signal exit"
    sys.exit(1)

# Function check that script run with sudo
def check_root():
    # Only root    	
    if not os.geteuid() == 0:
        print(RED + "[-] Script must run with 'sudo'" + ENDC)
        exit(1)

# Function sniffing packets
def sniffpackets(packet):
    try:
	SRCMAC = packet[0].addr2
	DSTMAC = packet[0].addr1
	BSSID = packet[0].addr3
    except:
	#print "Cannot read MAC address"
	#print str(packet).encode("hex")
	sys.exc_clear()
        return

    try:
	SSIDSize = packet[0][Dot11Elt].len
	SSID = packet[0][Dot11Elt].info
    except:
	SSID = ""
	SSIDSize = 0
    if (packet[0].type == 0):
	ST = packet[0][Dot11].subtype
	if (str(ST) == "8" and SSID != "" and DSTMAC.lower() == "ff:ff:ff:ff:ff:ff"):
	    p = packet[Dot11Elt]
	    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}" "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
	    channel = None
	    crypto = set()
	    while isinstance(p, Dot11Elt):
	        try:
		    if (p.ID == 3):
		        channel = ord(p.info)
		    elif (p.ID == 48):
		        crypto.add("WPA2")
		    elif (p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00')):
		        crypto.add("WPA")
		except:
		    pass
		p = p.payload
            if (not crypto):
                if ('privacy' in cap):
		    crypto.add("WEP")
		else:
		    crypto.add("OPN")
            if (SRCMAC not in ssid_list.keys()):
		if ('0050f204104a000110104400010210' in str(packet).encode("hex")):
	            crypto.add("WPS")
		print "[+] New AP {0:5}\t{1:20}\t{2:20}\t{3:5}".format(channel, BSSID, ' / '.join(crypto), SSID)
		ssid_list[SRCMAC] = SSID

def setup_monitor (iface):
    print(GREEN + "[+] Setting up sniff options..." + ENDC)
    os.system('ifconfig ' + iface + ' down')
    try:
        os.system('iwconfig ' + iface + ' mode monitor')
    except:
	print(RED + "[!] Failed to setup monitor mode" + ENDC)
	sys.exit(1)
    os.system('ifconfig ' + iface + ' up')
    return iface

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    logo()
    # Parser of arguments from command line	
    parser = argparse.ArgumentParser(description='[Coded by Shir, Hodaya & Alexey]', epilog="Please use the program for educational purposes.")
    parser.add_argument('-w', action='store', dest='wlan', type = str, help='iface for monitoring')
    parser.add_argument('-v', action='version', version='%(prog)s 1.0')
    results = parser.parse_args()
    banner()
    check_root()
    if "mon" not in str(results.wlan):
        newiface = setup_monitor(results.wlan)
    else:
	newiface = str(results.wlan)
    ssid_list = {}
    s = conf.L2socket(iface=newiface)
    print(GREEN + "[+] Sniffing on interface " + str(newiface) + "...\n" + ENDC)
    try: 
        sniff(iface=newiface, prn=sniffpackets, store=0)
    except Exception as ex:
        #print(ex)
        pass
    print(ssid_list)
