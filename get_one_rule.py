#!/usr/bin/env python

################################################################################

import requests
from requests.auth import HTTPBasicAuth
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse

################################################################################
###  Define Arguments for the script.
################################################################################

parser = argparse.ArgumentParser(description='Send API Request')
parser.add_argument('--nsx-mgr-ip', dest="ip",
                   help="NSX Manager IP", required=True)
parser.add_argument('--user', dest="user",
                   help="NSX Username, default: admin",
                   default="admin", required=False)
parser.add_argument('--password', dest="password",
                   help="NSX Password, default: VMware1!VMware1!",
                   default="VMware1!VMware1!", required=False)

args = parser.parse_args()


################################################################################
###  REST API function using python "requests" module
################################################################################
def rest_api_call (method, endpoint, data=None, ip=args.ip, user=args.user, password=args.password):
    url = "https://%s%s" % (ip, endpoint)
    # To remove ssl-warnings bug. even with cert verification is set as false
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    headers = {'Content-Type': 'application/json'}
    res = requests.request(
        method=method,
        url=url,
        auth=HTTPBasicAuth(user, password),
        headers=headers,
        data=data,
        verify=False
    )
    try:
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise e
    if len(res.content) > 0:
        response = res.json()
        return response

################################################################################
###  Define Arguments for the script.

rule_list = ["1","2","3"]

for n in rule_list :
    endpoint = "/policy/api/v1/infra/settings/firewall/security/intrusion-services/global-signatures/"+n
    result = rest_api_call(method= 'GET', endpoint = endpoint)
    print (result)
