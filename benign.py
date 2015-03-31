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

import requests
import argparse
import configparser

def submit_crits(domain):
    headers = {'User-agent': 'benign_domains'}

    # submit domain
    url = "{0}/api/v1/domains/".format(cfg.get('Maltrieve', 'crits')) 
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


def main():
	cfg = configparser.ConfigParser()
	cfg.read('benign.cfg')

	if cfg['benign'].getboolean('outputFile', fallback=False):
		print "output file"

	if cfg['benign'].getboolean('submitToCrits', fallback=False):
		print "submit to CRITs"


if __name__ == "__main__":
	try:
		main()
    except KeyboardInterrupt:
        sys.exit()