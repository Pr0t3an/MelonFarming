# Farming

Best intentions of somewhat maintaining some scripts to do some specific actions mostly for my own benefit - but if someone else finds them useful then whoop whoop.

---------------------------
<b>RiRiPy.py</b> Named after the delightful Rihanna - early version of script to invoke full functionality of Cisco Umbrella    / OpenDNS investigate - will only search one domain at the mo.

      Usage

        RiRIPy.py -h (self explanitory)
        RiRiPy.py -b (probably most useful at the mo - barebones info on the domain)

        Search 'CHANGEME' and update with your API key

      Planned

        Need to move away from optparse...was the quickest during dev
        Add support for output info to a file
        Add multi domain support - input from txt file/csv. Output to CSV or something

---------------------------

<b>pcapAlize.py</b> Prints unique IP's Split by SRC/DST in PCAP.
  
      Usage
          
          pcapAlize -h <file>.pcap
          (pretty much tshark -r <file>.pcap -T fields -e ip.src -e ip.dst | tr "\t" "\n" | sort | uniq
