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

def submit_crits(domain):
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
            logging.info("Submitted domain info for {0} to Crits, response was {1}".format(md5,
                         response_json.get('message', '')))
            if response_json['return_code'] == 0: 
                inserted_domain = True
    except:
        logging.info("Exception caught from Crits when submitting domain")


def check_virustotal(domain, cfg):
    """ Checks VirusTotal to see if the domain is malicious """

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'domain': domain, 
              'apikey': cfg['virustotal'].get('key'),
              'allinfo': 1}
    try:
        response = requests.get(url, params=params)

        if response.status_code == requests.codes.ok:
            response_json = response.json()
            logging.info("Submitted domain {0} to VirusTotal for verification, response was {1}".format(domain,
                         response_json('verbose_msg', '')))
            if response_json['response_code'] == 0:
                logging.info("VT: Has not seen {0} before, assuming domain is benign".format(domain))
                return True
            elif response_json['response_code'] == -1:
                logging.debug("VT: Reporting that domain {0} is malformed, assuming malicious".format(domain))
                return False
            elif response_json['response_code'] == 1:
                # Need to check a few things and then decide if it is really malicious.
                # probably Alexa domain info, Alexa category, Webutation domain info:Verdict, and maybe categories
                # For now just return True
                logging.info("VT: Category is: {0}".format(response_json.get('categories', ''))
                logging.info("VT: Webutation verdict is: {0}".format(response_json.get('Webutation domain info', ''))
                logging.info("VT: TrendMicro verdict is: {0}".format(response_json.get('TrendMicro category', ''))
                return True
    except:
        logging.debug("Exception caught from VirusTotal when receiving report")
        
    return False


def main():
    """ Main logic for program """
    print("Starting up benign_domain parsing script!!!")

    # Read configuration file
    cfg = configparser.ConfigParser()
    cfg.read('benign.cfg')

    # Set up logging functionality
    logfile = cfg['logging'].get('filename', fallback='benign.log')
    level = cfg['logging'].get('level', fallback='INFO').upper()
    logging.basicConfig(filename=logfile, level=level)
    print("Writing to log file {0} at level {1}.".format(logfile, level))

    inputFile = cfg['inputFile'].get('majestic', fallback='majestic_million.csv')
    print("Opening input file {0}.".format(inputFile))

    if cfg['benign'].getboolean('outputFile', fallback=True):
        outputFile = cfg['outputFile'].get('filename', fallback='benign.domains')
        print("Saving output to file {0}.".format(outputFile))

    if cfg['benign'].getboolean('submitToCrits', fallback=False):
        url = cfg['crits'].get('url', '')
        username = cfg['crits'].get('user', '')
        source = cfg['crits'].get('source', '')
        print("Submitting domains to CRITs at: \n\tURL: {0}\n\tUser: {1}\n\tSource: {2}".format(url, username, source))

    count = 0
    with open(inputFile) as infile:
        f_csv = csv.reader(infile)
        headings = next(f_csv)
        Row = namedtuple('Row', headings)
        for r in f_csv:
            if count == cfg['benign'].get('maxDomains', fallback=100):
                break
            row = Row(*r)
            
            if cfg['benign'].getboolean('checkVirustotal', fallback=False):
                if not check_virustotal(row.Domain, cfg):
                    continue

            if cfg['benign'].getboolean('outputFile', fallback=True):
                outputFile = cfg['outputFile'].get('filename', fallback='benign.domains')
                logging.info("Writing domain {0} to file {1}".format(row.Domain, outputFile))
                with open(outputFile, 'at') as f:
                   f.write(row.Domain + "\n")
                   #print(row.Domain, file=f)

            if cfg['benign'].getboolean('submitToCrits', fallback=False):
                submit_crits(row.Domain)

            count = count + 1
            time.sleep(float(cfg['benign'].get('wait', fallback='1.0')))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
