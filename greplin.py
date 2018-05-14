#!/usr/bin/python2.7

import os, sys, re, json
from argparse import ArgumentParser as AP


regexPattern = re.compile(
    r"(?P<remote_host>(^[a-zA-Z0-9_.-]*)\s)" 
    r"(?P<identity>\S*)\s" 
    r"(?P<remote_user>\S*)\s"
    r"\[(?P<time>.*?)\]\s"
    r'"(?P<request_method>([a-zA-Z0-9_.-]*)\s)'
    r'(?P<request>.*?)"\s'
    r"(?P<status>\d+)\s"
    r"(?P<bytes>\S*)\s"
    r'"(?P<referer>.*?)"\s'
    r'"(?P<user_agent>.*?)"\s*'
)


def main():
    parser = AP()
    parser.add_argument("-i", "--inputdir", dest="inputdir", help="InputDirectory",
                        required=True)
    parser.add_argument("-s", "--searchstring", dest="searchstring", help="Search String",
                        required=True)
    parser.add_argument("-o", "--outputdir", dest="outputdir", help="JSON Output Dir + Name", required=True)
    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    new = searchthis(args.inputdir, args.searchstring)
    with open(args.outputdir, 'w') as outfile:
        json.dump(new, outfile)


def searchthis(location, searchterm):
    d = []
    for dir_path, dirs, file_names in os.walk(location):
        for file_name in file_names:
            fullpath = os.path.join(dir_path, file_name)
            for line in file(fullpath):
                if searchterm in line:
                    try:
                        d.append(regexPattern.match(line).groupdict())
                    except:
                        sys.exit("Error Unable to Parse")

    return d


if __name__ == "__main__":
    main()
