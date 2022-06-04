"""
Copyright (c) 2022 Aleksandr Istomin, https://as.zabedu.ru

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from vra_ipam_utils.ipam import IPAM
import logging
import json


def handler(context, inputs):
    ipam = IPAM(context, inputs)
    IPAM.do_deallocate_ip = do_deallocate_ip
    return ipam.deallocate_ip()


def get_connection(self, auth_credentials, cert):
    end_props = self.inputs["endpoint"]["endpointProperties"]
    con = {'uri': f'https://{end_props["hostName"]}/api/{end_props["appId"]}/'}
    ignoreSslWarning = get_input_property(self.inputs, "ignoreSslWarning").lower() == "true"
    if ignoreSslWarning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        con['verify'] = False
    else:
        con['verify'] = cert
    if end_props["authType"] == "user":
        # User auth token
        auth = (auth_credentials["privateKeyId"], auth_credentials["privateKey"])
        resp = requests.post(con["uri"] + '/user/', auth=auth, verify=con['verify'])
        if resp.status_code != 200:
            raise requests.exceptions.RequestException('Authentication failure')
        con['token'] = {"token": resp.json()['data']['token']}
    else:
        # App code token
        con['token'] = {"token": auth_credentials["privateKey"]}
    return con


def do_deallocate_ip(self, auth_credentials, cert):
    con = get_connection(self, auth_credentials, cert)
    deallocation_result = []
    for deallocation in self.inputs["ipDeallocations"]:
        deallocation_result.append(deallocate(self.inputs["resourceInfo"], deallocation, con))
    assert len(deallocation_result) > 0
    return {
        "ipDeallocations": deallocation_result
    }


def deallocate(resource, deallocation, con):
    range_id = deallocation["ipRangeId"]
    ip = deallocation["ipAddress"]
    logging.info("Deallocating IP %s from range %s", ip, range_id)
    subnet_id = get_subnet_id(range_id)
    req_uri = f'{con["uri"]}/addresses/{ip}/{subnet_id}/'
    resp = requests.delete(req_uri, headers=con['token'], verify=con['verify'])
    resp = resp.json()
    if resp['success']:
        logging.info("Successfully deallocated %s", ip)
        return {
            "ipDeallocationId": deallocation["id"],
            "message": "Success"
        }
    else:
        raise Exception("Unable to deallocate IP")


def get_subnet_id(range_id):
    """
    Get network SubnetID by RangeID
    """
    return range_id.split(":")[0].split("/")[1]


def get_input_property(inputs, prop_key):
    """
    Get additional property from endpoint form
    """
    properties_list = inputs["endpoint"] \
                            ["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    for prop in properties_list:
        if prop.get("prop_key") == prop_key:
            return prop.get("prop_value")
    return None
