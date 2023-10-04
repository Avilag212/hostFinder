#!/usr/bin/python3
from scapy.all import ARP, Ether, srp
import socket
import re
import sys

class Finder:
    def __init__(self,range):
        regex_padrao = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        if re.match(regex_padrao, range):
            self.range = range
        else:
            raise ValueError("Invalid argument format!\nFormato de argumento inválido")

    def findHosts(self):
        ip_range = self.range
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        hosts = {}
        for sent, received in result:
            hosts.update({received.psrc:received.hwsrc})
        
        self.hosts = hosts

    def showHosts(self):
        for IP,MAC in self.hosts.items():
            try:
                hostname = socket.gethostbyaddr(IP)
                print(f"[+]Host encontrado: {hostname}")
            except:
                print(f"[+]Host encontrado: Unknown hostname")
            print(f"Endereço lógico: {IP}")
            print(f"Endereço físico: {MAC}\n")


if(__name__ == '__main__'):

    if(len(sys.argv)<2):
        print("\n")
        print("============ HOST FINDER ==============")
        print("         Developed By Avilag           ")
        print("This script find hosts on LAN with")
        print("ARP request for broadcast of range")
        print("specified.")
        print("=======================================")
        print("[WARNING]: Read the README.txt before use")
        print("[AVISO]: Leia o arquivo README.txt antes de usar")
    else:

        try:
            finder = Finder(sys.argv[1])
            finder.findHosts()
            finder.showHosts()
        except ValueError as erro:
            print(erro)
            print("[WARNING!]: Read the README.txt before use")
            print("[AVISO]: Leia o arquivo README.txt antes de usar")
        
        




