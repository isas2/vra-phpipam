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
    IPAM.do_update_record = do_update_record
    return ipam.update_record()


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


def do_update_record(self, auth_credentials, cert):
    con = get_connection(self, auth_credentials, cert)
    update_result = []
    resource = self.inputs["resourceInfo"]
    for update_record in self.inputs["addressInfos"]:
        update_result.append(update(resource, self.inputs, update_record, con))
    assert len(update_result) > 0
    return {
        "updateResults": update_result
    }


def update(resource, inputs, update_record, con):
    """
    Update MAC-addres by IP
    """
    try:
        mac = update_record["macAddress"]
        search = serach_ip(update_record["address"], con)
        if search['success']:
            update = update_mac(search['data'][0]['id'], mac, con)
            if update['success']:
                return "Success"
            else:
                raise update['message']
        else:
            raise search['message']
    except Exception as error:
        logging.error(f"Failed to update record {update_record}: {error}")
        raise error


def update_mac(id, mac, con):
    """
    Update MAC address
    """
    data = {'mac': mac}
    req_uri = f'{con["uri"]}/addresses/{id}'
    resp = requests.patch(req_uri, data=data, headers=con['token'], verify=con['verify'])
    return resp.json()


def serach_ip(ip, con):
    """
    Search IP address
    """
    req_uri = f'{con["uri"]}/addresses/search/{ip}/'
    resp = requests.get(req_uri, headers=con['token'], verify=con['verify'])
    return resp.json()


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
