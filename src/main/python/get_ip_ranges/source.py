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
import ipaddress
import json
import random

def handler(context, inputs):
    ipam = IPAM(context, inputs)
    IPAM.do_get_ip_ranges = do_get_ip_ranges
    return ipam.get_ip_ranges()


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


def do_get_ip_ranges(self, auth_credentials, cert):
    con = get_connection(self, auth_credentials, cert)
    dns_domain = get_input_property(self.inputs, "dnsDomain")
    vrfs = get_vrfs(con)
    subnets = get_subnets(self, con)
    ip_ranges = []
    for subnet in subnets:
        network_id = "phpipam/%s:%s/%s/%s" % (subnet["id"], subnet["subnet"], \
                subnet["mask"], str(vrfs.get(subnet["vrfId"])))
        network = ipaddress.ip_network(str(subnet['subnet']) + '/' + \
                str(subnet['mask']))
        ip_range = {
            'id': network_id,
            'name': str(network),
            'description': str(subnet['description']),
            'ipVersion': 'IPv' + str(network.version),
            'startIPAddress': str(network[1]),
            'endIPAddress': str(network[-2]),
            'subnetPrefixLength': str(subnet['mask']),
            'dnsSearchDomains': [dns_domain],
            'domain': dns_domain,
            'dnsServerAddresses': get_dns(subnet),
            'gatewayAddress': get_gateway(subnet['id'], network[1], con),
            'tags': [{
                'key': 'vlan',
                'value': subnet["custom_VLAN"]
            },{
                'key': 'location',
                'value': str(subnet.get("custom_Location"))
            }]
        }
        #logging.info("Found subnet: %s", network_id)
        ip_ranges.append(ip_range)
    logging.info("Found %s subnets", len(ip_ranges))
    return {'ipRanges': ip_ranges}


def get_vrfs(con):
    """
    Request list of VRFs
    """
    req_uri = f'{con["uri"]}/vrf/'
    resp = requests.get(req_uri, headers=con['token'], verify=con['verify'])
    resp = resp.json()['data']
    vrfs = {item['vrfId']:item['name'] for item in resp}
    return vrfs


def get_subnets(self, con):
    """
    Request list of subnets
    """
    req_uri = f'{con["uri"]}/subnets/'
    if self.inputs["endpoint"]["endpointProperties"]["enableFilter"] == "true":
        filterField = self.inputs["endpoint"]["endpointProperties"]["filterField"]
        filterValue = self.inputs["endpoint"]["endpointProperties"]["filterValue"]
        filter = f'filter_by={filterField}&filter_value={filterValue}'
        logging.info(f"Searching for subnets matching filter: {filter}")
    else:
        filter = ''
    resp = requests.get(f'{req_uri}?{filter}', headers=con['token'], verify=con['verify'])
    return resp.json()['data']


def get_gateway(subnet_id, network, con):
    """
    Get subnet gateway
    """
    req_uri = f'{con["uri"]}/subnets/{subnet_id}/addresses/'
    filter = 'filter_by=is_gateway&filter_value=1'
    resp = requests.get(f'{req_uri}?{filter}', headers=con['token'], verify=con['verify'])
    resp = resp.json()
    if resp['success'] == True:
        return resp['data'][0]['ip']
    else:
        ip_parts = str(network).split(".")
        return ".".join(ip_parts[:3] + ["1"])
        #return str(network)


def get_dns(subnet):
    """
    Get nameservers from IPAM
    """
    ns = subnet.get('nameservers')
    if ns != None:
        return [server.strip() for server in str(ns['namesrv1']).split(';')]
    else:
        return []


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
