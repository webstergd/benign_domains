#!/usr/bin/env python3

#################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2015, George Webster. All rights reserved.
#
# Approved for Public Release; Distribution Unlimited 14-1511
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#################################################################################

import argparse
import csv
import sys

from collections import namedtuple

def setup_cli(args):
    """ Configure command-line arguements """

    description = "outputs a list of domains between start and stop"
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-s', '--start', action='store',
                         dest='start', help='Start domain')
    parser.add_argument('-e', '--end', action='store',
                         dest='end', help='End domain')

    return parser.parse_args(args)


def main():
    """ Main logic for program """
    # Set up CLI interface
    args = setup_cli(sys.argv[1:])

    inputFile = 'majestic_million.csv'

    print("\nResults:\n--------------------------------------------------------------")
    with open(inputFile) as infile:
        f_csv = csv.reader(infile)
        headings = next(f_csv)
        Row = namedtuple('Row', headings)
        start = False

        for r in f_csv:
            row = Row(*r)

            if row.Domain == args.start:
                start = True
            
            if start:
                print("Processing domain: {0} at position: {1}".format(row.Domain, f_csv.line_num - 1))

                with open('quicklist', 'at') as f:
                   f.write(row.Domain + ",")
                   #print(row.Domain, file=f)

            if row.Domain == args.end:
                break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
