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
from datetime import datetime
from dns import resolver
from dns import reversename
import json


def handler(context, inputs):
    ipam = IPAM(context, inputs)
    IPAM.do_allocate_ip = do_allocate_ip
    return ipam.allocate_ip()


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


def do_allocate_ip(self, auth_credentials, cert):
    con = get_connection(self, auth_credentials, cert)
    allocation_result = []
    try:
        resource = self.inputs["resourceInfo"]
        for allocation in self.inputs["ipAllocations"]:
            allocation_result.append(allocate(self, resource, allocation, con))
    except Exception as error:
        try:
            rollback(allocation_result, con)
        except Exception as rollback_e:
            logging.error("Error during rollback of allocation result %s", str(allocation_result))
            logging.error(rollback_e)
        raise error

    assert len(allocation_result) > 0
    return {
        "ipAllocations": allocation_result
    }


def allocate(self, resource, allocation, con):
    """
    Get one free IP address and prepare sesult
    """
    last_error = None
    for range_id in allocation["ipRangeIds"]:
        logging.info("Allocating IP from range '%s'", range_id)
        try:
            return allocate_in_range(self, range_id, resource, allocation, con)
        except Exception as error:
            last_error = error
            logging.error("Failed to allocate IP in %s: %s", range_id, str(error))

    logging.error("No more ranges. Raising last error")
    raise last_error


def allocate_in_range(self, range_id, resource, allocation, con):
    custom_ip = allocation.get("start")
    if custom_ip is None:
        custom_ip = self.inputs["resourceInfo"]["properties"].get("custom_ip")
    if custom_ip in ["none", None]:
        # Get IP from IPAM
        ip_address = get_free_ip_with_check(self, range_id, resource, con)
    else:
        # Static IP from vRA
        ip_address = custom_ip
        logging.info("IP set manually: %s", ip_address)
        if not check_manual_ip(self, range_id, ip_address, resource, con):
            logging.info("IP %s already used or reserved", ip_address)
            raise Exception("Static IP already in use")
    if ip_address is not None:
        result = {
            "ipAllocationId": allocation["id"],
            "ipRangeId": range_id,
            "ipVersion": "IPv4",
            "ipAddresses": [ip_address]
        }
        logging.info("Successfully reserved %s for %s.", ip_address, resource['name'])
        return result
    else:
        raise Exception("No free IPs found")


def rollback(allocation_result, con):
    """
    Rollback any previously allocated addresses
    """
    for allocation in reversed(allocation_result):
        logging.info("Rolling back allocation %s", str(allocation))
        subnet_id = get_subnet_id(allocation.get("ipRangeId"))
        ip_addresses = allocation.get("ipAddresses", None)
        for ip_address in ip_addresses:
            req_uri = f'{con["uri"]}/addresses/{ip_address}/{subnet_id}/'
            requests.delete(req_uri, headers=con['token'], verify=con['verify'])


def get_free_ip_with_check(self, range_id, resource, con):
    """
    Get free IP in IPAM
    """
    prop_ping = get_input_property(self.inputs, "pingAllocatedAddress")
    prop_ptr = get_input_property(self.inputs, "checkAddressPtr")
    check = False
    while not check:
        resp = get_ip(self, range_id, resource, con)
        if resp['success']:
            # Check ip_address: ping and check PTR record
            ip_address = resp['data']
            check = check_ip_offline(prop_ping, ip_address, resp['id'], con)
            check = check and get_ptr_record(prop_ptr, ip_address)
            if not check:
                mark_ip(resp['id'], con)
        else:
            check = True
            ip_address = None
    logging.info("Reserved IP %s", ip_address)
    return ip_address


def check_manual_ip(self, range_id, ip, resource, con):
    """
    Check static IP (free or reserved for this vm_name) and create it
    """
    prop_ping = get_input_property(self.inputs, "pingAllocatedAddress")
    search = search_ip(ip, con)
    reserved = False
    if search['success']:
        hostname = search['data'][0]['hostname'].split(".")[0]
        reserved = search['data'][0]['tag'] == '3' and hostname == resource['name']
        if not check_ip_offline(prop_ping, ip, search['data'][0]['id'], con):
            return False
    if not search['success'] or reserved:
        data = {
            'hostname': resource['name'] + "." + get_input_property(self.inputs, "dnsDomain"),
            'description': f"Reserved by vRA for \'{resource.get('owner')}\' at {get_date()}",
            'tag': '2'
        }
        if reserved:
            return update_ip(search['data'][0]['id'], data, con)
        else:
            data['ip'] = ip
            data['subnetId'] = get_subnet_id(range_id)
            return create_ip(data, con)
    else:
        return False


def get_ip(self, range_id, resource, con):
    """
    Get first free IP from IPAM
    """
    subnet_id = get_subnet_id(range_id)
    data = {
        'hostname': resource['name'] + "." + get_input_property(self.inputs, "dnsDomain"),
        'description': f"Reserved by vRA for \'{resource.get('owner')}\' at {get_date()}"
    }
    req_uri = f'{con["uri"]}/addresses/first_free/{subnet_id}/'
    resp = requests.post(req_uri, data=data, headers=con['token'], verify=con['verify'])
    return resp.json()


def search_ip(ip, con):
    """
    Search IP address
    """
    req_uri = f'{con["uri"]}/addresses/search/{ip}/'
    resp = requests.get(req_uri, headers=con['token'], verify=con['verify'])
    return resp.json()


def check_ip_offline(start, ip_address, id, con):
    """
    Check (ping) IP address
    """
    if start == None or start.lower() != "true":
        return True
    req_uri = f'{con["uri"]}/addresses/{id}/ping/'
    resp = requests.get(req_uri, headers=con['token'], verify=con['verify'])
    resp = resp.json()
    result = resp['success'] and resp['data']['exit_code'] != 0
    logging.info("Check IP %s is offline: %s", ip_address, str(result))
    return result


def create_ip(data, con):
    """
    Create new IP address
    """
    req_uri = f'{con["uri"]}/addresses/'
    resp = requests.post(req_uri, data=data, headers=con['token'], verify=con['verify'])
    resp = resp.json()
    return resp['success']


def update_ip(id, data, con):
    """
    Update IP by ID
    """
    req_uri = f'{con["uri"]}/addresses/{id}'
    resp = requests.patch(req_uri, data=data, headers=con['token'], verify=con['verify'])
    resp = resp.json()
    return resp['success']


def mark_ip(id, con):
    """
    Mark an IP to not use it
    """
    data = {
        'hostname': 'error',
        'description': f"IP is online or has a PTR record {get_date()}",
        'tag': '3'
    }
    req_uri = f'{con["uri"]}/addresses/{id}'
    resp = requests.patch(req_uri, data=data, headers=con['token'], verify=con['verify'])
    resp = resp.json()
    return resp['success']


def get_subnet_id(range_id):
    """
    Get network SubnetID from RangeID
    """
    return range_id.split(":")[0].split("/")[1]


def get_ptr_record(start, ip_address):
    """
    Check PTR record in DNS
    """
    if start == None or start.lower() != "true":
        return True
    try:
        addr = reversename.from_address(ip_address)
        resp = resolver.resolve(addr, "PTR")
        if len(resp) > 0:
            logging.info("IP address %s already used: %s", ip_address, ", ".join(map(str, resp)))
            return False
    except resolver.NXDOMAIN as e:
        logging.info("Check IP %s PTR record: not found", ip_address)
        return True
    except resolver.NoAnswer as e:
        logging.info("No answer from DNS server")
        return False
    except resolver.Timeout as e:
        logging.info("DNS request timeout error")
        return False


def get_date():
    """
    Get formated date
    """
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")


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