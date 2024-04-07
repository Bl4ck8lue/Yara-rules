#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
"""
clamav_to_yara.py

Created by Matthew Richard on 2010-03-12.
Copyright (c) 2010 __MyCompanyName__. All rights reserved.
"""

import os
import re
from optparse import OptionParser


def main():
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", dest="filename",
                      type="string", help="scanned FILENAME")
    parser.add_option("-o", "--output-file", action="store", dest="outfile",
                      type="string", help="output filename")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      dest="verbose", help="verbose")
    parser.add_option("-s", "--search", action="store", dest="search",
                      type="string", help="search filter", default="")

    (opts, args) = parser.parse_args()

    if opts.filename is None:
        parser.print_help()
        parser.error("You must supply a filename!")
    if not os.path.isfile(opts.filename):
        parser.error("%s does not exist" % opts.filename)

    if opts.outfile is None:
        parser.print_help()
        parser.error("You must specify an output filename!")

    yara_rule = """
rule %s {
    strings:
        %s
    condition:
        %s
}

        """
    rules = {}
    output = ""
    data = open(opts.filename, 'rb').readlines()

    if (opts.filename.endswith(".cvd") or opts.filename.endswith(".cld")) and data[0].find("ClamAV".encode()) == 0:
        print("It seems you're passing a compressed database.")
        print("Try using sigtool -u to decompress first.")
        return

    print("[+] Read %d lines from %s" % (len(data), opts.filename))

    # ClamAV signatures are one per line
    for line in data:
        # signature format is
        # name:sigtype:offset:signature
        try:
            vals = line.split(b':')
            if len(vals) < 4 or len(vals) > 6:
                print("**ERROR reading ClamAV signature file**")
                continue
            name = vals[0]
            sigtype = vals[1]
            offset = vals[2]
            signature = vals[3]
        except:
            print("**ERROR reading ClamAV signature file**")
            continue
        # if specified, only parse rules that match a search criteria
        if opts.search in name.decode():

            # sanitize rule name for YARA compatability
            # YARA does not allow non-alphanumeric chars besides _
            rulename_regex = re.compile('(\W)')
            rulename = rulename_regex.sub('_', name.decode())

            # and cannot start with a number
            rulename_regex = re.compile('(^[0-9]{1,})')
            rulename = rulename_regex.sub('', rulename)

            # if the rule doesn't exist, create a dict entry
            if rulename not in rules:
                rules[rulename] = []

            # handle the ClamAV style jumps
            # {-n} is n or less bytes
            jump_regex = re.compile('(\{-(\d+)\})')
            signature = jump_regex.sub('{0-\g<2>}', signature.decode())

            # {n-} is n or more bytes
            jump_regex = re.compile('(\{(\d+)-\})')
            matches = jump_regex.findall(signature)

            if matches:
                for match in matches:
                    # print "\t\tfound %s" % (match[1])
                    start = int(match[1])
                    jump_regex = re.compile('(\{(%d)-\})' % (start))
                    if start < 256:
                        # print "\t\t\tfound short jump of len %d" % (start)
                        signature = jump_regex.sub('[0-\g<2>]', signature)
                    else:
                        # print "\t\t\tfound long jump, replacing with '*'"
                        signature = jump_regex.sub('*', signature)

            # {n-m} is n to m bytes
            # need to make sure it's not bigger than 255,
            # and the high bound cannot exceed 255
            # if it is we'll treat it like a '*'
            jump_regex = re.compile('(\{(\d+)-(\d+)\})')
            matches = jump_regex.findall(signature)

            if matches:
                for match in matches:
                    # print "\t\tfound %s - %s" % (match[1], match[2])
                    start = int(match[1])
                    end = int(match[2])
                    jump_regex = re.compile('(\{(%d)-(%d)\})' % (start, end))
                    if end - start == 0:
                        if opts.verbose:
                            print("\t**Skip nothing, impossible!**")
                        signature = jump_regex.sub('', signature)
                    elif (end - start < 256) and (end < 256):
                        # print "\t\t\tfound short jump of len %d" % (end - start)
                        signature = jump_regex.sub('[\g<2>-\g<3>]', signature)
                    else:
                        # print "\t\t\tfound long jump, replacing with '*'"
                        signature = jump_regex.sub('*', signature)

            # {n} bytes
            # here we must also enforce the 255 byte maximum jump
            # that YARA can handle
            jump_regex = re.compile('(\{(\d+)\})')
            matches = jump_regex.findall(signature)

            if matches:
                for match in matches:
                    # print "\t\tfound %s" % (match[1])
                    start = int(match[1])
                    jump_regex = re.compile('(\{(%d)\})' % (start))
                    if start < 256:
                        # print "\t\t\tfound short jump of len %d" % (start)
                        signature = jump_regex.sub('[\g<2>]', signature)
                    else:
                        # print "\t\t\tfound long jump, replacing with '*'"
                        signature = jump_regex.sub('*', signature)

            # translate the '*' operator into a pair of signatures
            # with an 'and'
            if '*' in signature:
                for part in signature.split('*'):
                    if part[0] != '(':
                        rules[rulename].append(part.strip())
            else:
                if signature[0] != '(':
                    rules[rulename].append(signature.strip())

    for rule in rules.keys():
        detects = ''
        conds = "\t"
        x = 0
        for detect in rules[rule]:
            # print(detect)
            y = 0
            new_detect = ''
            if detect[0] == '?' or detect[1] == '?':
                new_detect = '' + detect[2:]
            if detect[len(detect)-1] == ']':
                numb_for_lasts_bytes = int(detect[len(detect)-2])
                new_detect = detect[:len(detect)-3]
                for i in range(0, numb_for_lasts_bytes, 1):
                    new_detect += '??'
            name_rule = rule[:23]
            if name_rule == "Pdf_Exploit_Agent_35528" or name_rule == "Pdf_Exploit_Agent_35529" or name_rule == "Pdf_Exploit_Agent_35530":
                new_detect = detect[:203]
            elif name_rule == "Pdf_Exploit_Agent_35531" or name_rule == "Pdf_Exploit_Agent_35532":
                new_detect = detect[:201]
            # print(new_detect)
            if detect[0] == 'T' and detect[1] == 'h' and detect[2] == 'i' and detect[3] == 's':
                detects += "$a{0} = \"{1}\"\r\n".format(x, detect)
                y = 1
            if y == 0:
                if new_detect == '':
                    detects += "$a{0} = {{{1}}}\r\n".format(x, detect)
                else:
                    detects += "$a{0} = {{{1}}}\r\n".format(x, new_detect)
            if x > 0:
                conds += " and "
            conds += "$a%d" % x
            x += 1
        if detects == '':
            if opts.verbose:
                print("\t**Found empty rule %s, skipping**" % rule)
            continue
        else:
            output += yara_rule % (rule, detects, conds)

    if len(output) > 0:
        print("\r\n[+] Wrote %d rules to %s\r\n" % (len(rules), opts.outfile))
        fout = open(opts.outfile, 'wb')
        fout.write(output.encode())
        fout.close()
    else:
        print("\r\n**Could not find any signatures to convert!!!**\r\n")


if __name__ == '__main__':
    print("\n" + '#' * 75)
    print("\t" + "Malware Analyst's Cookbook - ClamAV to YARA Converter 0.0.1")
    print("\n" + '#' * 75, "\n")

    main()