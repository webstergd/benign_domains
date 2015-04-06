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
import configparser
import csv
import logging
import requests
import sys
import time

from collections import namedtuple
from itertools import islice

def submit_crits(domain, cfg):
    """ Submits domain to CRITs """
    headers = {'User-agent': 'benign_domains'}

    # submit domain
    url = "{0}/api/v1/domains/".format(cfg['crits'].get('url')) 
    params = {
        'api_key': cfg['crits'].get('key'),
        'username': cfg['crits'].get('user'),
        'source': cfg['crits'].get('source'),
        'domain': domain
    }
    try:
        response = requests.post(url, headers=headers, data=params, verify=False)
        if response.status_code == requests.codes.ok:
            response_json = response.json()
            logging.info("\tSubmitted domain info for {0} to Crits, response was {1}".format(domain,
                         response_json.get('message', '')))
    except:
        logging.info("Exception caught from Crits when submitting domain {0}".format(domain))


def check_virustotal(domain, api_key, threshold):
    """ Checks VirusTotal to see if the domain is malicious """
    #resource = "{0}domain".format("http://www.", domain)

    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'resource': domain, 
              'apikey': api_key,
              'allinfo': 1}
    try:
        response = requests.get(url, params=params)

        if response.status_code == requests.codes.ok:
            response_json = response.json()
            logging.info("\tSubmitted domain {0} to VirusTotal for verification, response was {1}".format(domain,
                         response_json.get('verbose_msg', '')))
            if response_json['response_code'] == 0:
                logging.info("\tVT: Has not seen {0} before, assuming domain is benign".format(domain))
                return True
            elif response_json['response_code'] == -1:
                logging.debug("\tVT: Reporting that domain {0} is malformed, assuming malicious".format(domain))
                return False
            elif response_json['response_code'] == 1:
                total = int(response_json.get('total', 0))
                positive = int(response_json.get('positives', 0))

                additionalinfo = response_json.get('additional_info', '')
                if additionalinfo:
                    logging.info("\tVT: Category is: {0}".format(additionalinfo.get('categories', '')))
                logging.info("\tVT: Positive scans: {0} out of {1} total scans".format(positive, total))

                if positive > int(threshold):
                    logging.info("\tVT: Threshold exceeded, skipping domain")
                    return False
                else:
                    logging.info("\tVT: Under threshold, domain is benign")
                    return True
    except:
        logging.debug("Exception caught from VirusTotal when receiving report")
        
    return False


def setup_cli(args, cfg):
    """ Configure command-line arguements """

    description ="""
    Benign_domains outputs a list of preceived benign domains. This is
    intended to help gather data for ML training sets and generate white
    lists. The core set of domains are provided by majestic million.
    
    Options:
        - Validate domains against VirusTotal's datasets (in progress)
        - Submit domains to a CRITs instance
        - Output to a file"""

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-s', '--start', action='store', default=cfg['benign'].get('startDomain', fallback='0'),
                         dest='start', type=int, help='Define starting domain rank number. Overrides config file')
    parser.add_argument('-e', '--end', action='store', default=cfg['benign'].get('endDomain', fallback='200'),
                         dest='end', type=int, help='Define ending domain rank number. Overrides config file')

    return parser.parse_args(args)


def main():
    """ Main logic for program """
    print("Starting up benign_domain parsing script!!!")

    # Read configuration file
    cfg = configparser.ConfigParser()
    cfg.read('benign.cfg')

    # Set up CLI interface
    args = setup_cli(sys.argv[1:], cfg)

    # Set up logging functionality
    logfile = cfg['logging'].get('filename', fallback='benign.log')
    level = cfg['logging'].get('level', fallback='INFO').upper()
    logformat = '%(asctime)s %(message)s'
    logging.basicConfig(filename=logfile, level=level, format=logformat)
    print("Writing to log file {0} at level {1}.".format(logfile, level))

    inputFile = cfg['inputFile'].get('majestic', fallback='majestic_million.csv')
    print("Opening input file {0}.".format(inputFile))
    print("Starting processing at domain {0}".format(args.start))
    print("Ending processing at domain {0}".format(args.end))

    if cfg['benign'].getboolean('outputFile', fallback=True):
        outputFile = cfg['outputFile'].get('filename', fallback='benign.domains')
        print("Saving output to file {0}.".format(outputFile))

    if cfg['benign'].getboolean('submitToCrits', fallback=False):
        url = cfg['crits'].get('url', '')
        username = cfg['crits'].get('user', '')
        source = cfg['crits'].get('source', '')
        print("Submitting domains to CRITs at: \n\tURL: {0}\n\tUser: {1}\n\tSource: {2}".format(url, username, source))

    # Quick checks before entering the loop
    if args.start == 0:
        args.start = 1
    if args.start > args.end:
        print("Starting # must be greater then ending #.\nExiting")
        sys.exit()
    if int(cfg['virustotal'].get('threshold', 0)) < 1:
        print("Threshold must be greater then 0, setting to 1")
        cfg['virustotal']['threshold'] = 1

    print("\nResults:\n--------------------------------------------------------------")
    with open(inputFile) as infile:
        f_csv = csv.reader(infile)
        headings = next(f_csv)
        Row = namedtuple('Row', headings)

        for r in islice(f_csv, args.start - 1, args.end):
            row = Row(*r)
            
            print("Processing domain: {0} at position: {1}".format(row.Domain, f_csv.line_num - 1))
            logging.info("Processing domain: {0} at position: {1}".format(row.Domain, f_csv.line_num - 1))

            if cfg['benign'].getboolean('checkVirustotal', fallback=False):
                if not check_virustotal(row.Domain, cfg['virustotal'].get('key'), cfg['virustotal'].get('threshold')):
                    continue

            if cfg['benign'].getboolean('outputFile', fallback=True):
                outputFile = cfg['outputFile'].get('filename', fallback='benign.domains')
                logging.info("\tWriting domain {0} to file {1}".format(row.Domain, outputFile))
                with open(outputFile, 'at') as f:
                   f.write(row.Domain + "\n")
                   #print(row.Domain, file=f)

            if cfg['benign'].getboolean('submitToCrits', fallback=False):
                submit_crits(row.Domain, cfg)

            time.sleep(float(cfg['benign'].get('wait', fallback='1.0')))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
