#!/usr/bin/env python

#Extracts and prints unique IP's in PCAP seperated by Src/Dst

# you will need dpkt

import dpkt
import sys
import getopt
import socket

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def dashu(input_pcap):
    print input_pcap
    f = open(input_pcap)
    pcap = dpkt.pcap.Reader(f)
    strsrcip = [0]
    strdestip = [0]
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if inet_to_str(ip.src) not in strsrcip:
            strsrcip.append(inet_to_str(ip.src))
        if inet_to_str(ip.dst) not in strdestip:
            strdestip.append(inet_to_str(ip.dst))
    print bcolors.BOLD + "\nUnique Source IP's\n"
    print bcolors.ENDC
    for ili in strsrcip:
        if ili != 0:
            print ili
    print bcolors.BOLD + "\nUnique Destination IP's\n"
    print bcolors.ENDC
    for ili in strdestip:
        if ili != 0:
            print ili
    print "\n"

try:
    opts, args = getopt.getopt(sys.argv[1:], "hu:", ["help", "unique"])
except getopt.GetoptError:
    print "ERR Syntax error try with -h to view available options"
for opt, args in opts:
    if opt in ("-h", "help"):
        print "-u print unique IP's Split by IP.src and IP.dst"
    if opt in ("-u", "unique"):
        dashu(args)
       
       
