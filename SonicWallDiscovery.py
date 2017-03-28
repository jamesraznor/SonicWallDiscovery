#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    --------------------------------------------
     Copyright 2015. TRADESYS | Soluções em TI. 
-------------------------------------------------------
Designed by 'james souza' | +5511 42238086 or 985863257
james.souza@tradesys.com.br or jamesraznor@me.com
--------------------------------------------------------

FOR MACOSX ONLY. tested on MacBook Pro 15inch.
* How to use :
    *You need to start program and then connect SonicWall port XO.
    *All devices stating with SonicWall "vendorOUI's" will be discovered.

* PS:
 Display IP, know devices like TZ210... NSA2600... but has no firmware version info.
- This program is open and should be shared to all. be free to improve this code.

* USE OF THE SOFTWARE IS AT USER'S OWN RISK. 
Neither me or Tradesys are not resposable for any kind of damage.
 - Terms for the components permit User to copy, 
 modify and redistribute the component, in both source code and binary code forms.  
 - This agreement does not limit User's rights under, 
 or grant User rights that supersede, the license terms of any particular component.

'''
try:
    from scapy.all import *
    from time import sleep
    from termcolor import colored
except Exception, e:
    print('[-] Please, You need todo "sudo -H pip install scapy" or "sudo easy_install scapy". \
            \n--> Error: %s ') % e
    exit(0)

''' scan arp, grap IPaddress and ask for combination '''
'''  Vendor's OUI '''
a_sonicwall = "00:06:b1"
b_sonicwall = "00:17:c5"
c_sonicwall = "18:b1:69"
d_sonicwall = "c0:ea:e4"
e_sonicwall = "18:b1:69"
f_sonicwall = "00:17:cB"
g_sonicwall = "00:17:c0"
h_sonicwall = "00:17:cc"
i_sonicwall = "00:17:c1"
j_sonicwall = "00:17:cE"

'''  Append Devices '''
alreadyfound = []

'''  Begin Function broadcast '''
def broadcast(pkt):
    if pkt.haslayer(ARP) and pkt.getlayer(ARP):
        if pkt[ARP].op == 2:
            response = "--> SonicWall is at: " + pkt[ARP].hwsrc + "\tIP address " + pkt[ARP].psrc + "\t"
            if a_sonicwall in response:
                return response + colored("Possible Guess - SonicWall Pro 4060", 'cyan', attrs=['bold'])
            if b_sonicwall in response:
                return response + colored("Possible Guess - SonicWall NSA 3500 / TZ 210",'cyan', attrs=['bold'])
            elif c_sonicwall in response:
                return response + colored("Possible Guess - SonicWall TZ 300 W. / SOHO", 'cyan', attrs=['bold'])
            elif d_sonicwall in response:
                return response + colored("Possible Guess - SonicWall TZ Series / NSA Series.",'cyan', attrs=['bold'])
            elif e_sonicwall in response:
                return response + colored("Possible Guess - SonicWall TZ 300 W.",'cyan', attrs=['bold'])
            elif f_sonicwall in response:
                return response
            elif g_sonicwall in response:
                return response
            elif h_sonicwall in response:
                return response
            elif i_sonicwall in response:
                return response
            elif j_sonicwall in response:
                return response
def main():
    if __name__ == "__main__":
        print colored('[*] Searching SonicWall devices. Please, wait...', \
                'white', attrs=['bold', 'blink'])
        sleep(6)
        print colored('[!] Please, SonicWall must be connected on Port: X0.', \
                'white', attrs=['bold', 'reverse']) 
        sniff(prn=broadcast, filter='arp', store=0)
main()
