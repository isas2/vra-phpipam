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
from vra_ipam_utils.exceptions import InvalidCertificateException
import logging
import json


def handler(context, inputs):
    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint
    return ipam.validate_endpoint()


def get_connection(self, auth_credentials, cert):
    end_props = self.inputs["endpointProperties"]
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


def do_validate_endpoint(self, auth_credentials, cert):
    try:
        con = get_connection(self, auth_credentials, cert)
        resp = check_token(con)
        if resp.status_code == 200:
            return {
                "message": "Validated successfully",
                "statusCode": "200"
            }
        elif resp.status_code == 500 and resp.json()['message'] == 'Invalid username or password':
            logging.error("Invalid credentials error: %s", str(response.content))
            raise Exception("Invalid credentials error: %s", str(response.content))
        else:
            raise Exception("Failed to connect: %s", str(response.content))
    except Exception as e:
        """ In case of SSL validation error, a InvalidCertificateException is raised.
            So that the IPAM SDK can go ahead and fetch the server certificate
            and display it to the user for manual acceptance.
        """
        if "SSLCertVerificationError" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or 'certificate verify failed' in str(e):
            logging.error("SSL validating error: %s", str(e))
            if get_input_property(self.inputs, "ignoreSslWarning").lower() != "true":
                raise InvalidCertificateException("certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from e
        else:
            raise e


def check_token(con):
    req_uri = f'{con["uri"]}/user/'
    resp = requests.get(req_uri, headers=con['token'], verify=con['verify'])
    return resp


def get_input_property(inputs, prop_key):
    """
    Get additional property from endpoint form
    """
    properties_list = inputs["endpointProperties"].get("properties", [])
    properties_list = json.loads(properties_list)
    for prop in properties_list:
        if prop.get("prop_key") == prop_key:
            return prop.get("prop_value")
    return None
