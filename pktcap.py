#!/usr/bin/env python3
# -*- encoding:utf-8 -*-

import getopt
import sys
import datetime
import time
import os
import re
import pymysql


from scapy.layers import http as HTTP
from scapy.error import Scapy_Exception
from scapy.all import *

def CapturePacket(interface, count, filter):
    print("Start capture...")
    packets = sniff(iface=interface, filter=filter, count=count)
    for packet in packets:
        AnlysisPacket(packet)
    print(packets)
    try:
        pcap_filepath = 'pkts/pkts_{}.pcap'.format(time.strftime("%Y%m%d-%H%M%S",
            time.localtime()))
        pcap_file = open(pcap_filepath, 'wb')
        wrpcap(pcap_file, packets)
    except Exception as e:
        pcap_file.close()
        pass

def AnlysisPacket(packet):
    src = packet[IP].src
    srcport = packet[IP].sport
    dst = packet[IP].dst
    dstport = packet[IP].dport
    proto = packet[IP].proto
    rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    #test = packet[TCP].payload
    #print(packet)
    if srcport == 80 or dstport == 80:
        AnlysisHTTP(packet)
    if srcport == 53 or dstport == 53:
        AnlysisDNS(packet)
    if srcport == 23 or dstport == 23:
        AnlysisTelnet(packet)
    if srcport == 21 or dstport == 21:
        AnlysisFTP(packet)
    db = pymysql.connect("localhost", "myuser", "hh911717+", "protocol_db")
    cursor = db.cursor()
    sql = "INSERT INTO protocol_tb(ip_src, ip_sport, ip_dst, ip_dport, \
          protocol_nu,Timestamp) VALUES ('%s', %d, '%s', %d, %d, '%s')" % \
          (src, srcport, dst, dstport, proto, rtime)
    try:
        cursor.execute(sql)
        db.commit()
    except Exception as e:
        db.rollback()
    db.close()


def AnlysisFTP(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        print("======================================================================")
        print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print("IP: %s:%s -> %s:%s" % (
            packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport) )
        user_name = None
        passwords = None
        ftp_load = packet[Raw].payload
        try:
            if '230' in ftp_load:
                print("\033[1;31;1mFTP:\033[0m")
                user_name = ftp_load.split('USER')[1].strip()
                passwords = ftp_load.split('PASS')[1].strip()
                print("USER: %s" % user_name)
                print("PASSWORDS: %s" % passwords)
                rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
                db = pymysql.connect("localhost", "myuser", "hh911717+", "protocol_db")
                cursor = db.cursor()
                sql = "INSERT INTO ftp_tb(user, password, timestamp) VALUES ('%s', '%s', '%s')" % (user_name, passwords, rtime)
                try:
                    cursor.execute(sql)
                    db.commit()
                except Exception as e:
                    db.rollback()
                db.close()
            res = error_detection(str(packet))
            if res:
                print("\033[1;31;1mWarning:The packet is illegal\033[0m")
                for row in res:
                    print("\033[1;31;1m%s\033[0m" % row)
                error_data(packet)
        except Exception as e:
            print(e)

def AnlysisDNS(packet):
    if packet.haslayer(DNS):
        print("======================================================================")
        print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print("IP: %s:%s -> %s:%s" % (
            packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport) )
        try:
            dns_fields = packet[DNS].fields
            dns_qr = dns_fields['qr']
            dns_tc = dns_fields['tc']
            dns_aa = dns_fields['aa']
            print("\033[1;31;1mTransaction ID:%s\033[0m" % dns_fields['id'])
            print("Flags:")
            if dns_qr == 0:
                print("QR=%d .........Response:Message is a query" % dns_fields['qr'])
                print("Opcode=%d...Opcode: Standard query " % dns_fields['opcode'])
                if dns_tc == 0:
                    print("TC=%d..........Truncated: Message is not truncated" % dns_fields['tc'])
                if dns_tc == 1:
                    print("TC=%d..........Truncated: Message is truncated" % dns_fields['tc'])
                print("RD=%d..........Recursion desired" % dns_fields['rd'])
            if dns_qr == 1:
                print("QR=%d .........Response: Message is a response" % dns_fields['qr'])
                print("Opcode=%d......Opcode: Standard response " % dns_fields['opcode'])
                if dns_aa == 0:
                    print("AA=%d.........Authoritative: Server is not an authority for domain")
                if dns_aa == 1:
                    print("AA=%d.........Authoritative: Server is an authority for domain")
                if dns_tc == 0:
                    print("TC=%d..........Truncated: Message is not truncated" % dns_fields['tc'])
                if dns_tc == 1:
                    print("TC=%d..........Truncated: Message is truncated" % dns_fields['tc'])
                print("RD=%d..........Recursion desired" % dns_fields['rd'])
                print("RA=%d..........Recursion available" % dns_fields['ra'])
            print("z=%d...........Reserved" % dns_fields['z'])
            print("rcode=%d.......Reply code" % dns_fields['rcode'])
            print("Questions: %d\nAnswer RRs: %d\nAuthority RRs: %d\nAdditional RRs: %d" % (
                dns_fields['qdcount'], dns_fields['ancount'], dns_fields['nscount'], dns_fields['arcount']
            ))
            dns_qname = processStr(packet[DNS].qd.qname)
            print("Queries:\n %s" % (dns_qname))
            if dns_qr == 1 and packet[DNS].an != None:
                dns_rname = processStr(packet[DNS].an.rrname)
                dns_rdata = packet[DNS].an.rdata
                print("Answers:\n %s %s" % (dns_rname, dns_rdata))
            rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            db = pymysql.connect("localhost", "myuser", "hh911717+", "protocol_db")
            cursor = db.cursor()
            sql = "INSERT INTO dns_tb(queries, answers, timestamp) VALUES ('%s', '%s', '%s')" % (dns_qname, dns_rdata, rtime)
            try:
                cursor.execute(sql)
                db.commit()
            except Exception as e:
                db.rollback()
            db.close()
            res = error_detection(str(packet))
            if res:
                print("\033[1;31;1mWarning:The packet is illegal\033[0m")
                for row in res:
                    print("\033[1;31;1m%s\033[0m" % row)
                error_data(packet)
        except Exception as e:
           print(e)
        print("======================================================================")

def AnlysisHTTP(packet):
    if packet.haslayer(HTTP.HTTPRequest):
        print("======================================================================")
        print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print("IP: %s:%s -> %s:%s" % (
            packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport))
        try:
            print("\033[1;31;1mHTTP Request:\033[0m")
            http_name = 'HTTP Request'
            http_header = packet[HTTP.HTTPRequest].fields
            for key, val in http_header.items():
                value = processStr(val)
                print("%s:%s" % (key, value))
            host = processStr(packet[HTTP.HTTPRequest].fields['Host'])
            path = processStr(packet[HTTP.HTTPRequest].fields['Path'])
            method = processStr(packet[HTTP.HTTPRequest].fields['Method'])
            use_agent = processStr(packet[HTTP.HTTPRequest].fields['User_Agent'])
            rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            db = pymysql.connect("localhost", "myuser", "hh911717+", "protocol_db")
            cursor = db.cursor()
            sql = "INSERT INTO httprequest_tb(host, path, method, user_agent,timestamp) VALUES ('%s', '%s', '%s', '%s', '%s')" % \
                  (host, path, method, use_agent, rtime)
            try:
                cursor.execute(sql)
                db.commit()
            except Exception as e:
                db.rollback()
            db.close()
            res = error_detection(str(packet))
            if res:
                print("\033[1;31;1mWarning:The packet is illegal\033[0m")
                for row in res:
                    print("\033[1;31;1m%s\033[0m" % row)
                error_data(packet)
        except Exception as e:
            print(e)
        print("======================================================================")

    if packet.haslayer(HTTP.HTTPResponse):
        print("======================================================================")
        print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print("IP: %s:%s -> %s:%s" % (
            packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport))
        try:
            print("\033[1;31;1mHTTP Response:\033[0m")
            http_name = 'HTTP Response'
            http_header = packet[HTTP.HTTPResponse].fields
            for key, val in http_header.items():
                value = processStr(val)
                print("%s:%s" % (key, value))
            http_payload = packet[HTTP.HTTPResponse].payload
            if not http_payload is None:
                print("Payload:")
                print(processStr(http_payload))
            connection = processStr(packet[HTTP.HTTPResponse].fields['Connection'])
            status_code = processStr(packet[HTTP.HTTPResponse].fields['Status_Code'])
            rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            db = pymysql.connect("localhost", "myuser", "hh911717+", "protocol_db")
            cursor = db.cursor()
            sql = "INSERT INTO httpresponse_tb(connection, status_code, timestamp) VALUES ('%s', '%s', '%s')" % \
                  (connection, status_code, rtime)
            try:
                cursor.execute(sql)
                db.commit()
            except Exception as e:
                db.rollback()
            db.close()
            res = error_detection(str(packet))
            if res:
                print("\033[1;31;1mWarning:The packet is illegal\033[0m")
                for row in res:
                    print("\033[1;31;1m%s\033[0m" % row)
                error_data(packet)
        except Exception as e:
            print(e)
        print("======================================================================")

def AnlysisTelnet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        print("======================================================================")
        print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        print("IP: %s:%s -> %s:%s Timestamp: %s" % (
            packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport, ))
        print(packet[Telnet].fields)
        res = error_detection(str(packet))
        if res:
            print("\033[1;31;1mWarning:The packet is illegal\033[0m")
            for row in res:
                print("\033[1;31;1m%s\033[0m" % row)
        print("======================================================================")

def processStr(data):
    pattern = re.compile('^b\'(.*?)\'$', re.S)
    res = re.findall(pattern, str(data))
    final = res[0]
    return final

def error_detection(s):
    db = pymysql.connect("localhost", "myuser", "hh911717+", "error_db")
    cursor = db.cursor()
    sql = "SELECT * FROM exceptionrule_table"
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        res = []
        for row in results:
            re = KMP(s, row[1])
            if re :
                res.append(row[1])
        return res
    except Exception as e:
        print(e)
    db.close()

def error_data(packet):
    src = packet[IP].src
    srcport = packet[IP].sport
    dst = packet[IP].dst
    dstport = packet[IP].dport
    proto = packet[IP].proto
    rtime = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    db = pymysql.connect("localhost", "myuser", "hh911717+", "error_db")
    cursor = db.cursor()
    sql = "INSERT INTO exception_tb (ip_src, ip_sport, ip_dst, ip_dport, \
          protocol_nu,Timestamp) VALUES ('%s', %d, '%s', %d, %d, '%s')" % \
          (src, srcport, dst, dstport, proto, rtime)
    try:
        cursor.execute(sql)
        db.commit()
    except Exception as e:
        print(e)
        db.rollback()
    db.close()

def KMP(s, p):
    nex = getnext(p)
    i = j = 0
    while i < len(s) and j < len(p):
        if j == -1 or s[i] == p[j]:
            i += 1
            j += 1
        else:
            j = nex[j]

    if j == len(p):
        return i - j
    else:
        return None

def getnext(p):
    next = [0] * len(p)
    next[0] = -1
    i = 0
    j = -1
    while i < len(p) - 1:
        if j == -1 or p[i] == p[j]:
            i += 1
            j += 1
            next[i] = j
        else:
            j = next[j]

    return next

def main(argv):
    count = 0
    filter = None
    try:
        opts, args = getopt.getopt(argv, "i:f:c:", ["interface=", "filter=","count="])
    except getopt.GetoptError:
        print('pktcap.py -i or -interfance ')
        sys.exit()
    for opt, arg in opts:
        if opt in ("-i", "--interface"):
            interface = arg
        elif opt in ("-f", "--filter"):
            filter = arg
        elif opt in ("-c","--count"):
            count = int(arg)
    CapturePacket(interface, count, filter)

if __name__ == "__main__":
    main(sys.argv[1:])