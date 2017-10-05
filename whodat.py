#!/usr/bin/env python

# uses pycountry
# pip install pycountry
# Super basic script Alpha_2 to Country Name
# Embarrassed to event publish - but will save me a bit of time finding it in the future

import sys
import pycountry
if len(sys.argv) == 2:
    try:
        country = pycountry.countries.get(alpha_2=sys.argv[1].upper())
        print '\n' + country.name + '\n'
    except:
        "Not Found...sorry"
else:
    print "Need to enter in a 2 Letter country code.. whodat.py DE"



