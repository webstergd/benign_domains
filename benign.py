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
import requests
import logging

def submit_crits(domain):
    headers = {'User-agent': 'benign_domains'}

    # submit domain
    url = "{0}/api/v1/domains/".format(cfg.get('crits', 'url')) 
    domain_data = {
        'api_key': cfg.crits_key,
        'username': cfg.crits_user,
        'source': cfg.crits_source,
        'domain': domain
    }
    try:
        # Note that this request does NOT go through proxies
        domain_response = requests.post(url, headers=headers, data=domain_data, verify=False)
        if domain_response.status_code == requests.codes.ok:
            domain_response_data = domain_response.json()
            logging.info("Submitted domain info for %s to Crits, response was %s" % (md5,
                         domain_response_data["message"]))
            if domain_response_data['return_code'] == 0: 
                inserted_domain = True
    except:
        logging.info("Exception caught from Crits when submitting domain")

def scan_virustotal(domain):
    pass

def main():
    print("Starting up benign_domain parsing script!!!")

    # Read configuration file
    cfg = configparser.ConfigParser()
    cfg.read('benign.cfg')

    # Set up logging functionality
    if cfg['benign'].getboolean('logging', fallback=True):
        logfile = cfg['logging'].get('filename', fallback='benign.log')
        level = cfg['logging'].get('level', fallback='INFO').upper()
        logging.basicConfig(filename=logfile, level=level)
        print("Writing to log file {0} at level {1}.".format(logfile, level))

    if cfg['benign'].getboolean('checkVirustotal', fallback=False):
        print("Checking domains against VirusTotal for validity")

    if cfg['benign'].getboolean('outputFile', fallback=True):
        outputFile = cfg['outputFile'].get('filename', fallback='benign.domains')
        print("Saving output to file {0}.".format(outputFile))

    if cfg['benign'].getboolean('submitToCrits', fallback=False):
        url = cfg['crits'].get('url', '')
        username = cfg['crits'].get('user', '')
        source = cfg['crits'].get('source', '')
        print("Submitting domains to CRITs at: \n\tURL: {0}\n\tUser: {1}\n\tSource: {2}".format(url, username, source))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()