#!/usr/bin/env python

import getopt
import sys
from urllib2 import Request
from urllib2 import urlopen
import ssl
import re
import json
import os
import optparse
import argparse
import re



class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# API Documentation - https://investigate-api.readme.io

def riri_err(helpmess):
    # Error Handling
    print bcolors.FAIL + '\n\n' + helpmess + '\n'
    print bcolors.ENDC
    sys.exit(2)

# Single Request Function
def riri_singlerequest(requesthandler):
    # API Key Modified Below
    riri_apikey = 'CHANGEME'
    headers = {
        'Authorization': 'Bearer ' + riri_apikey,
        "User-Agent": "RiRi-Umbrella-Api"
    }

    request = Request(requesthandler, headers=headers)
    sslreq=ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    try:
        response_body = urlopen(request, context=sslreq).read()
        return response_body
    except urllib2.HTTPError, e:
        checksLogger.error('HTTPError = ' + str(e.code))
    except urllib2.URLError, e:
        checksLogger.error('URLError = ' + str(e.reason))
    except httplib.HTTPException, e:
        checksLogger.error('HTTPException')
    except Exception:
        import traceback
        checksLogger.error('generic exception: ' + traceback.format_exc())


def dashd(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/domains/categorization/' + tdomain + "?showLabels"
    stroutput = riri_singlerequest(temph)
    pattern = re.search(r'(status":(.*),"sec)', stroutput)
    umclass = pattern.group(2)
    pattern = re.search(r'(security_categories":\[(.*)\],"content)', stroutput)
    umseccat = pattern.group(2)
    pattern2 = re.search(r'(content_categories":\["(.*)"\])', stroutput)
    if pattern2:
        umcat = pattern2.group(2)
    else:
        umcat= "None"
    if umclass == '-1':
        umclass = 'malicious'
    elif umclass == '1':
        umclass = 'benign'
    elif umclass == '0':
        umclass = 'not yet categorized'
    if umseccat == "":
        umseccat = "None"
    print '\n\nDomain: ' + tdomain + ' \nclass: ' + umclass + ' \nSecurity Classification: ' + umseccat + ' \nSite Category: ' + umcat + '\n\n'

def dashf(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/whois/' + tdomain
    stroutput = riri_singlerequest(temph)
    parsed_json = json.loads(stroutput)
    try:
        print json.dumps(parsed_json, sort_keys=True, indent=4, separators=(',', ': '))
    except:
        print "JSON Parsing Error"

def dashw(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/whois/' + tdomain
    stroutput = riri_singlerequest(temph)
    parsed_json = json.loads(stroutput)
    print bcolors.UNDERLINE + '\n\nCondensed Whois: ' + tdomain + '\n'
    print bcolors.ENDC
    try:
        print('Registrant Organization:  ' + parsed_json['registrantOrganization'])
    except:
        print('Registrant Organization::  N\A')
    try:
        print('Created:  ' + parsed_json['created'])
    except:
        print('Created:  N\A')
    try:
        print('Updated:  ' + parsed_json['updated'])
    except:
        print('Updated:  N\A')
    try:
        print('Expires:  ' + parsed_json['expires'])
    except:
        print('Expires:  N\A')
    try:
        print('Administrative Contact Organization:  ' + parsed_json['administrativeContactOrganization'])
    except:
        print('Administrative Contact Organization:  N\A')
    try:
        print('Whois Servers:  ' + parsed_json['whoisServers'])
    except:
        print 'Whois Servers:  N\A'
    try:
        print('Domain Name:  ' + parsed_json['domainName'])
    except:
        print ('Domain Name:  N\A')
    try:
        print('Administrative Contact Email:  ' + parsed_json['administrativeContactEmail'])
    except:
        print('Administrative Contact Email:  N\A')
    print '\n\n'
    # print('\n Full Whois\n\n')
    # print json.dumps(parsed_json, sort_keys=True, indent=4, separators=(',', ': '))

# request = Request('https://investigate.api.umbrella.com/recommendations/name/' + tdomain + '.json', headers=headers)
# Co-occurying domains...ref https://umbrella.cisco.com/blog/2013/07/24/co-occurrences/  i.e. temporal proximity

def dashc(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/recommendations/name/' + tdomain + '.json'
    stroutput = riri_singlerequest(temph)
    parsed_json = json.loads(stroutput)

    print bcolors.UNDERLINE + '\n\nCo-Occurring Temporal Domains: ' + tdomain + '\n'
    print bcolors.ENDC
    try:
        tempvar = parsed_json['found']
        if tempvar:
            print "\nFollowing Co-Occurrences Identified: (Domain\Percentage) \n"
            descript = parsed_json['pfs2']
            arrlength = len(descript)
            i = 0
            while i < arrlength:
                descript[i][1] = round((descript[i][1] * 100), 2)
                i = i + 1

            s = [[str(e) for e in row] for row in descript]
            lens = [max(map(len, col)) for col in zip(*s)]
            fmt = '\t'.join('{{:{}}}'.format(x) for x in lens)
            table = [fmt.format(*row) for row in s]
            print '\n'.join(table)
            print '\n'
    except:
        print "No Co-Occurrences Identified\n"

    # print json.dumps(parsed_json, sort_keys=True, indent=4, separators=(',', ': '))


# https://investigate.api.umbrella.com/links/name/example.com.json"


def dashr(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/links/name/' + tdomain + '.json'
    print temph
    stroutput = riri_singlerequest(temph)
    parsed_json = json.loads(stroutput)
    # Array of [domain name, scores] tuples where score is the number of client IP requests to the site around the
    # same time as the site being looked up. This is a score reflecting the number of client IPs looking up related
    # sites within 60 seconds of the original request.
    print bcolors.UNDERLINE + '\n\nDomains Visited within 60s of Target Domain: ' + tdomain + '\n'
    print bcolors.ENDC
    try:
        if parsed_json['found']:
            descript = parsed_json['tb1']
            s = [[str(e) for e in row] for row in descript]
            lens = [max(map(len, col)) for col in zip(*s)]
            fmt = '\t'.join('{{:{}}}'.format(x) for x in lens)
            table = [fmt.format(*row) for row in s]
            print '\n'.join(table)
            print '\n'

    except:
        print "No related domains found"


def dashs(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/security/name/'+tdomain +'.json'
    stroutput = riri_singlerequest(temph)
    parsed_json = json.loads(stroutput)
    print bcolors.UNDERLINE + '\n\nSecurity info for: ' + tdomain + '\n'
    print bcolors.ENDC
    if parsed_json['found']:
        print '\nThreat Type : ' + parsed_json['threat_type']
        print 'Attack       : ' + parsed_json['attack']
        print 'Entrophy     : ' + str(round(parsed_json['entropy'], 2))
        print 'Fast Flux    : ' + str(parsed_json['fastflux'])
        print '\nScore -100 Suspicious 0 Benign\n'
        print 'DGA Score    : ' + str(round(parsed_json['dga_score'], 2))
        print 'Rip Score    : ' + str(round(parsed_json['rip_score'], 2))
        print 'Prefix Score : ' + str(round(parsed_json['prefix_score'], 2))
        print 'ASN Score    : ' + str(round(parsed_json['asn_score'], 2))
        print 'Page Rank    : ' + str(round(parsed_json['pagerank'], 2))
#        print '\nSecure Rank     : ' + str(round(parsed_json['securerank'], 2))
        print 'Secure Rank 2: ' + str(round(parsed_json['securerank2'], 2))
        print 'ASN Score    : ' + str(round(parsed_json['asn_score'], 2))
        print 'Popularity (Unique  IPs vs others    : ' + str(round(parsed_json['popularity'], 2))
        descript = parsed_json['geodiversity']
        print "\nRequestor Geo Distribution (%).\n"
        arrlength = len(descript)
        i = 0
        while i < arrlength:
            descript[i][1] = round((descript[i][1] * 100), 2)
            i = i + 1
        s = [[str(e) for e in row] for row in descript]
        lens = [max(map(len, col)) for col in zip(*s)]
        fmt = '\t'.join('{{:{}}}'.format(x) for x in lens)
        table = [fmt.format(*row) for row in s]
        print '\n'.join(table)
        print '\n'


def dashb(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/domains/' + tdomain + '/latest_tags'
    stroutput = riri_singlerequest(temph)
    if stroutput == '[]':
        print 'No Domain Tagging'
    else:
        chars_to_remove = ['[', ']', "u'", '{', '}']
        parsed_json = json.loads(stroutput)
        # print parsed_json
        print bcolors.UNDERLINE + '\n\nDomain Categorisation History: ' + tdomain
        print bcolors.ENDC
        i = 0
        arrl = len(parsed_json)
        print "\n\nCategory                 URL                      Start Period            End Period"
        while i < arrl:
            newstr = str(parsed_json[i])
            test = newstr.translate(None, ''.join(chars_to_remove))
            test = test.replace(',', ':')
            test = test.split(':')
            ltest = len(test)
            cat = str(test[1])
            cat += ' ' *(25 - len(cat))
            url = str(test[3])
            url += ' ' * (25 - len(url))
            pstart = str(test[6])
            pstart += ' ' * (25 - len(pstart))
            pend = str(test[8])
            if pend == ' Crrent':
                pend = 'Current'
            pend += ' ' * (25 - len(pend))
            print cat + url + pstart + pend
            i = i + 1
        print '\n\n'


def pp_json(json_thing, sort=True, indents=4):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
    return None


def dasht(domain2search):
    tdomain = domain2search
    dtype= ['A', 'NS', 'MX', 'TXT', 'CNAME']
    i = 0
    while i < 5:
        print 'DNS RR History for: ' + tdomain + ' Record Type: ' + dtype[i]
        temph = "https://investigate.api.umbrella.com/dnsdb/name/" + dtype[i] + "/" + tdomain + ".json"
    # A, NS, MX, TXT and CNAME
        stroutput = riri_singlerequest(temph)
        parsed_json = json.loads(stroutput)
        if parsed_json['rrs_tf']:
            pp_json(stroutput)
        else:
            print 'NO RECORDS Identified'
        print '\n'
        i = i + 1

def dashi(domain2search):
    tdomain = domain2search
    dtype = ['A', 'NS', 'MX', 'TXT', 'CNAME']
    i = 0
    while i < 5:
        print 'DNS RR History for: ' + tdomain + ' Record Type: ' + dtype[i]
        temph = "https://investigate.api.umbrella.com/dnsdb/ip/" + dtype[i] + "/" + tdomain + ".json"
        # A, NS, MX, TXT and CNAME
        stroutput = riri_singlerequest(temph)
        parsed_json = json.loads(stroutput)
        if parsed_json['rrs']:
            pp_json(stroutput)
        else:
            print 'NO RECORDS Identified'
        print '\n'
        i = i + 1


def dashl(domain2search):
    tdomain = domain2search
    temph = 'https://investigate.api.umbrella.com/ips/' + tdomain + '/latest_domains'
    stroutput = riri_singlerequest(temph)
    if stroutput == '[]':
        print ' No Malware Domains identified on IP'
    else:
        chars_to_remove = ['[', ']', '"', '{', '}']
        parsed_json = json.loads(stroutput)
        # print parsed_json
        i = 0
        arrl = len(parsed_json)
        print "\n\n" + str(arrl) + ' Malicious Domains Identified on IP: ' + tdomain
        if str(arrl) == "1000":
            print 'LIMIT REACHED: Displaying 1000 records'
        while i < arrl:
            newstr = str(parsed_json[i])
            test = newstr.translate(None, ''.join(chars_to_remove))
            test = test.replace(',', ':')
            test = test.split(':')
            print str(i) + ' ' + (test[3].strip("'"))[3:]
            i = i + 1
        print '\n\n'


print"\n\n"
print ",---.    ,-. ,---.    ,-.              .-. .-.           ,---.   ,---.     ,---.   ,-.     ,-.       .--.   "
print "| .-.\   |(| | .-.\   |(|              | | | | |\    /|  | .-.\  | .-.\    | .-'   | |     | |      / /\ \  "
print "| `-'/   (_) | `-'/   (_)   ____.___   | | | | |(\  / |  | |-' \ | `-'/    | `-.   | |     | |     / /__\ \ "
print "|   (    | | |   (    | |   `----==='  | | | | (_)\/  |  | |--. \|   (     | .-'   | |     | |     |  __  | "
print "| |\ \   | | | |\ \   | |              | `-')| | \  / |  | |`-' /| |\ \    |  `--. | `--.  | `--.  | |  |)| "
print "|_| \)\  `-' |_| \)\  `-'              `---(_) | |\/| |  /( `--' |_| \)\   /( __.' |( __.' |( __.' |_|  (_) "
print "    (__)         (__)                          '-'  '-' (__)         (__) (__)     (_)     (_)              "

print"\n Under my Cisco umbrella...ella...ella...eh..eh...eh"
print "ASCII art all the things"

# Helpfunction
def riri_help():
    print"\n\n"
    print" ____  ____  ____  ____           _   _  ____  __    ____  "
    print"(  _ \(_  _)(  _ \(_  _)   ___   ( )_( )( ___)(  )  (  _ \ "
    print" )   / _)(_  )   / _)(_   (___)   ) _ (  )__)  )(__  )___/ "
    print"(_)\_)(____)(_)\_)(____)         (_) (_)(____)(____)(__)   "
    print"\n"
    print"-----------------------------------------------------------"
    print "\n\nriri.py -h ...display help\n\n"
    print "ERROR Indicates API Key has not been set"
    print "\nOptions..."
    print ' -d ...domain will search single domain'
    print ' -w ....basic whois lookup single domain'
    print ' -f ....Co-Occurring Temporal Domains'
    print ' -r ....Related Domains based on Activity'
    print ' -s ....Domain Security Info'
    print ' -b ....Block list Info'
    print ' -t ....DNS RR history for Domain (All Supported Record Types)'
    print ' -i ....DNS RR history for IP '
    print ' -l ....Malware Domains By IP'
    print ' -r ....Domain Investigation'
    print '\n\nTODO:\nbasic tidying up\nsupport for multiple arguments\noutput support\ncsv,txt input'


try:
    opts, args = getopt.getopt(sys.argv[1:], "hd:w:f:c:r:s:b:t:i:l:r:", ["help", "singsearch", "swhois", "sfwhois", "sco", "related", "secinfo", "blocklist"])
except getopt.GetoptError:
    riri_err("ERR Syntax error try with -h to view available options")
for opt, args in opts:
    if opt in ("-h", "help"):
        riri_help()
    if opt in ("-d", "--singsearch"):
        dashd(args)
    if opt in ("-w", "swhois"):
        dashw(args)
    if opt in ("-f", "sfwhois"):
        dashf(args)
    if opt in ("-c", "sco"):
        dashc(args)
    if opt in ("-r", "related"):
        dashr(args)
    if opt in ("-s", "secinfo"):
        dashs(args)
    if opt in ("-b", "blocklist"):
        dashb(args)
    if opt in ("-t"):
        dasht(args)
    if opt in ("-i"):
        dashi(args)
    if opt in ("-l"):
        dashl(args)
    if opt in ("-r"):
        dashd(args)
        dashw(args)
        dashb(args)
