# Farming

Best intentions of somewhat maintaining some scripts to do some specific actions mostly for my own benefit - but if someone else finds them useful great.

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

-----------------------------

<b>whodat.py</b> Basic 2 Char (Alpha-2) country code to Country name lookup using pycountry

      Requirements - pycountry (pip install pycountry)
      
      Usuage - whoday.py <2 letter code>
      
----------------------------

<b>yabs.py</b> YABS - Yet Another Bucket Scanner.  Scanning for S3 public buckets against a worklist.  Many exist but needed something that would be able to run huge word lists - so needed to use the ThreadPoolExecutor.  I had some things added (probably not deleted, to track progress...but wont be using it often enough so cat <file> | wc -l or Get-Content <file> | Measure-Object -Line  will do the trick.
      
      Usuage - yabs.py -h 
      
      usage: yabs.py [-h] [-w scanlist] [-o outputfile] [-s] [-p]
               [-c concurrentthreads]

optional arguments:
  -h, --help            show this help message and exit
  -w scanlist, --scanlist scanlist
                        Text file containing domain safe list to scan
  -o outputfile, --outputfile outputfile
                        Output file defaults to scanout.txt
  -s, --silent          Silent mode only prints public buckets to the console
  -p, --perftest        takes the first 50 entries in the wordlist and
                        calculates the anticipated time for completion then
                        extrapolates this to provide estimate for processing
                        entire list
  -c concurrentthreads, --concurrentthreads concurrentthreads
                        specific the number of concurrent threads, use with
                        caution

