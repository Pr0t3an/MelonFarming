#!/usr/bin/python2.7

from argparse import ArgumentParser
import sys

def main():
    parser = ArgumentParser()
    parser.add_argument("-r", "--rulename", dest="rulename", help="Name of Rule (no spaces use underscore)", metavar="rulename", required=True)
    parser.add_argument("-o", "--outputfile", dest="outputfile", help="Output Directory of Yara file", metavar="outputfile", required=True)
    parser.add_argument("-s", "--sig", dest="destiredsig", help="Signature", metavar="destiredsig", required=True)
    parser.add_argument("-n", "--newfile", dest="newfile", help="Only Look for New Files submitted/analysed", action='store_true')
    parser.add_argument("-v", "--avvendor", dest="avvendor", help="Single av vendor kaspersky, mcafee, etc", required=True)


    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    genYara(args.outputfile, args.destiredsig, args.newfile, args.rulename, args.avvendor)


def genYara(outdir, sig, newfile, rulename, avvendor):
    yarfile = outdir + rulename + ".yara"
    file = open(yarfile, "w")
    file.write('rule %s\n{\n\tcondition:\n' % (rulename))
    if newfile:
        file.write('\t\tnew_file\n\t\tand\n\t\t(\n\t\t\t%s contains \"%s\"\n\t\t)\n' % (avvendor,sig))
    else:
        file.write('\t(\n\t\t%s\"%s\"\n\t)\n' % (avvendor, sig))
    file.write('}')
    file.close()



if __name__ == "__main__":
    main()
