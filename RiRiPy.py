#!/usr/bin/python

from urllib2 import Request
from urllib2 import urlopen
import os
import sys
import getopt
import ssl

# Work in Progress for Implementing Python SCript to interact with Cisco Umbrealla Open DNS investigate API.
# Will be adding in read and write from file, delays etc.

# Setup requiredAUTH
# Umbrella API URL - https://investigate.api.umbrella.com/"
# Per DOCS - header in the form - "Authorization: Bearer %YourToken%"
# Purpose is purely passive - no posting or recategorization

# update this here if hardcoding Token, need to set riritk below also
manualTk = True

# Options -d (domain)
dashd = False

# grab token Value
if not manualTk:
    riritk = os.getenv('token', False)
else:
    riritk = 'xxInsertYerTokenHere'

if not riritk:
    print "Why you no set token...re-run like so...token=%Umbrella Token% python riripy.py or set manually"
    sys.exit(1)

print "Token " + riritk

# Read Cat of single domain
# curl -H "Authorization: Bearer %YourToken%"
# "https://investigate.api.umbrella.com/domains/categorization/example.com?showLabels"



# Set Universal Header for request per
# https://docs.umbrella.com/developer/investigate-api/domain-status-and-categorization-1/

headers = {
    'Authorization': 'Bearer ' + riritk
}



try:
    opts, args = getopt.getopt(sys.argv[1:], "hd:", ["singsearch="])
except getopt.GetoptError:
    print 'ERR riripy.py -d <domain>'
    sys.exit(2)
for opt, args in opts:
    if opt == '-h':
        print ' usage riripy.py -d <domain>'
        print ' -d ...domain will search single domain'
    elif opt in ("-d", "--singsearch"):
        tdomain = args
        dashd = True
        print "t domain = " + tdomain

# Submit and output query on single domain
# "https://investigate.api.umbrella.com/domains/categorization/example.com?showLabels"
if dashd:
    request = Request('https://investigate.api.umbrella.com/domains/categorization/' + tdomain + '?showLabels', headers=headers)
    sslreq=ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    response_body = urlopen(request, context=sslreq).read()
    print "Domain: " + tdomain
    print "Token: " + riritk
    print "\n\n"
    print "response" + response_body



