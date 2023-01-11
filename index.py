import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Address
import threading

# working dir
cwd = os.getcwd()
def sudoCheck():
    if not "SUDO_UID" in os.environ.keys():
        print("Acces Denied, Are you root?")
        exit(1)
        
def arpScan(ipRange):
    arpResponses = list()
    answeredList = scapy.arping(ipRange, verbose=0)[0]
    for res in answeredList:
        arpResponses.append({"ip" : res[1].prsc, "mac" : res[1].hwsrc})
    return arpResponses

def isGateway(gatewayIp):
    result = subprocess.run(["route", "-n"], captureOutput=True).stdout.decode().split("\n")
    for row in result:
        if gatewayIp in row:
            return True 
    return False
   
    