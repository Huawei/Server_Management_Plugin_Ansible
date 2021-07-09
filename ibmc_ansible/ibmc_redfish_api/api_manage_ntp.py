#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import requests

from ibmc_ansible.utils import set_result
from .api_manage_ibmc_ip import get_ibmc_ip_request

NTP_DICT = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "static": "Static"
}

# Minimum polling interval
MIN_POLLING_INTERVAL = 3
# Maximum polling interval
MAX_POLLING_INTERVAL = 17


def set_ntp(ibmc, ntp_info):
    """
    Function:
        Set NTP configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        ntp_info : User-set NTP information
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         The min or max polling interval is illegal!
    Date: 2019/10/12 17:21
    """
    ibmc.log_info("Start set NTP configuration resource info...")

    # Obtain user-configured NTP information
    service_enabled = ntp_info.get('service_enabled')
    pre_ntp_server = ntp_info.get('pre_ntp_server')
    alt_ntp_server = ntp_info.get('alt_ntp_server')
    server_auth_enabled = ntp_info.get('server_auth_enabled')
    ntp_address_origin = ntp_info.get('ntp_address_origin')
    min_polling_interval = ntp_info.get('min_polling_interval')
    max_polling_interval = ntp_info.get('max_polling_interval')

    # Initialize return information
    ret = {'result': True, 'msg': ''}
    # Initialize payload
    payload = {}

    # Enable or disable iBMC NTP service, The optional parameters are: true or false
    if service_enabled is not None:
        if isinstance(service_enabled, bool):
            payload["ServiceEnabled"] = service_enabled
        else:
            log_msg = 'The service enabled is incorrect, It should be True or False'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Config preferred NtpServer, you can enter ipv4 ipv6 or domain name
    # NTP Server will be blanked when set to an empty string
    if pre_ntp_server is not None:
        payload["PreferredNtpServer"] = pre_ntp_server

    # Config alternate NtpServer, you can enter ipv4 ipv6 or domain name
    # NTP Server will be blanked when set to an empty string
    if alt_ntp_server is not None:
        payload["AlternateNtpServer"] = alt_ntp_server

    # Enable or disable Server Authentication service, The optional parameters are: true or false
    if server_auth_enabled is not None:
        if isinstance(server_auth_enabled, bool):
            payload["ServerAuthenticationEnabled"] = server_auth_enabled
        else:
            log_msg = 'The server authentication enabled is incorrect, It should be True or False'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Config Ntp Address Origin, The optional parameters are: "IPv4", "IPv6" or "Static"
    # When the IPv4 address origin is static, cannot set ntp address origin to IPv4.
    # When the IPv6 address origin is static, cannot set ntp address origin to IPv6.
    if ntp_address_origin:
        ntp_address_origin = NTP_DICT.get(str(ntp_address_origin).lower())
        current_ip_version, current_ipv4_addr_origin, current_ipv6_addr_origin \
            = get_current_ip(ibmc)
        rets = check_ip_version(ibmc, ntp_address_origin, current_ip_version,
                                current_ipv4_addr_origin,
                                current_ipv6_addr_origin)
        if rets.get("result") is False:
            return rets
        if ntp_address_origin in NTP_DICT.values():
            payload["NtpAddressOrigin"] = ntp_address_origin
        else:
            log_msg = 'The ntp address origin is incorrect, It should be "IPv4", "IPv6" or "Static"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Config Min Polling Interval time, in 3~17 and <= MaxValue
    # Config Max Polling Interval time, in 3~17 and >= MinValue
    try:
        rets = check_set_interval(ibmc, min_polling_interval,
                                  max_polling_interval)
        if rets.get("result") is False:
            return rets
        if min_polling_interval is not None:
            payload["MinPollingInterval"] = min_polling_interval
        if max_polling_interval is not None:
            payload["MaxPollingInterval"] = max_polling_interval
    except ValueError as e:
        msg = "The min or max polling interval is illegal! The error info is: %s \n" % str(
            e)
        ibmc.log_error(msg)
        raise ValueError(msg)

    # If the input parameter is empty, prompt the user to enter the correct parameter in the yml file
    if payload == {}:
        log_msg = 'The parameter is empty, please enter the correct parameter in the set_ntp.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    ret = set_ntp_request(ibmc, payload)
    return ret


def check_set_interval(ibmc, min_polling_interval, max_polling_interval):
    """
    Function:
        Verify the validity of the min_polling_interval and max_polling_interval setted by the user.
    Args:
        ibmc : Class that contains basic information about iBMC
        min_polling_interval : User-set min polling interval
        max_polling_interval: User-set max polling interval
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2019/10/12 17:21
    """
    ret = {'result': True, 'msg': ''}

    if min_polling_interval is not None:
        # Verify min_polling_interval is an integer
        if not isinstance(min_polling_interval, int):
            log_msg = 'The min polling interval must be an integer'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if min_polling_interval < MIN_POLLING_INTERVAL or min_polling_interval > MAX_POLLING_INTERVAL:
            log_msg = 'The min polling interval is incorrect, It should be a integer from %s to %s' % \
                      (str(MIN_POLLING_INTERVAL), str(MAX_POLLING_INTERVAL))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    if max_polling_interval is not None:
        # Verify max_polling_interval is an integer
        if not isinstance(max_polling_interval, int):
            log_msg = 'The max polling interval must be an integer'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if max_polling_interval < MIN_POLLING_INTERVAL or max_polling_interval > MAX_POLLING_INTERVAL:
            log_msg = 'The max polling interval is incorrect, It should be a integer from %s to %s' % \
                      (str(MIN_POLLING_INTERVAL), str(MAX_POLLING_INTERVAL))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    if (min_polling_interval is not None) and (
            max_polling_interval is not None):
        if min_polling_interval > max_polling_interval:
            log_msg = 'The min polling interval cannot be greater than max polling interval'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    return ret


def check_ip_version(ibmc, ntp_address_origin, current_ip_version,
                     current_ipv4_addr_origin, current_ipv6_addr_origin):
    """
    Function:
        Check if the IP version can be changed
    Args:
        ibmc : Class that contains basic information about iBMC
        ntp_address_origin : User-set ntp address origin
        current_ip_version: current server ip version
        current_ipv4_addr_origin: current ipv4 addr origin
        current_ipv6_addr_origin : current ipv6 addr origin
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2019/10/12 17:21
    """
    ret = {'result': True, 'msg': ''}
    if current_ip_version == "IPv4AndIPv6":
        if ntp_address_origin == "IPv4" and current_ipv4_addr_origin == "Static":
            log_msg = 'The current IPv4 address origin is Static, cannot set ntp address origin to IPv4'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if ntp_address_origin == "IPv6" and current_ipv6_addr_origin == "Static":
            log_msg = 'The current IPv6 address origin is Static, cannot set ntp address origin to IPv6'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    elif current_ip_version == "IPv4":
        if ntp_address_origin == "IPv4" and current_ipv4_addr_origin == "Static":
            log_msg = 'The current IPv4 address origin is Static, cannot set ntp address origin to IPv4'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if ntp_address_origin == "IPv6":
            log_msg = 'The current ip version is IPv4, cannot set ntp address origin to IPv6'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    elif current_ip_version == "IPv6":
        if ntp_address_origin == "IPv4":
            log_msg = 'The current ip version is IPv6, cannot set ntp address origin to IPv4'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if ntp_address_origin == "IPv6" and current_ipv6_addr_origin == "Static":
            log_msg = 'The current IPv6 address origin is Static, cannot set ntp address origin to IPv6'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    return ret


def get_current_ip(ibmc):
    """
    Function:
        get current ntp info
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        current_ip_version: current server ip version
        current_ipv4_addr_origin: current ipv4 addr origin
        current_ipv6_addr_origin : current ipv6 addr origin
    Raises:
         None
    Date: 2019/10/12 17:21
    """
    # Get the current IPv4 and IPv6 address origin
    request_result_json = get_ibmc_ip_request(ibmc)
    current_ip_version = ""
    current_ipv4_addr_origin = ""
    current_ipv6_addr_origin = ""
    oem_info = ibmc.oem_info

    try:
        # Obtain current ip version
        current_ip_version = request_result_json["Oem"][oem_info]["IPVersion"]

        # Obtain current IPv4 address origin
        ipv4_addr_list = request_result_json["IPv4Addresses"]
        current_ipv4_addr_origin = ipv4_addr_list[0]["AddressOrigin"]

        # Obtain current IPv6 address origin
        ipv6_addr_list = request_result_json["IPv6Addresses"]
        current_ipv6_addr_origin = ipv6_addr_list[0]["AddressOrigin"]
    except Exception as e:
        ibmc.log_error(
            "Get iBMC current ip version, IPv4 and IPv6 address origin failed! "
            "The error info is: %s \n" % str(e))
    ibmc.log_info(
        "The current ip version is: %s, The current IPv4 address origin is: %s, "
        "The current IPv6 address origin is: %s"
        % (current_ip_version, current_ipv4_addr_origin,
           current_ipv6_addr_origin))

    return current_ip_version, current_ipv4_addr_origin, current_ipv6_addr_origin


def set_ntp_request(ibmc, payload):
    """
    Function:
        set NTP configuration
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/10/12 21:13
    """
    ret = {'result': True, 'msg': ''}
    # URL of the NTP service
    url = ibmc.manager_uri + "/NtpService"
    # Obtain token
    token = ibmc.bmc_token
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token,
               'If-Match': etag}
    try:
        # Modify NTP configuration by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=10)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set NTP configuration resource info successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set NTP configuration resource info failed! The error code is: %s, " \
                      "The error info is: %s." % (
                          str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        msg = "Set NTP configuration resource info failed! The error info is: %s" % str(
            e)
        ibmc.log_error(msg)
        raise requests.exceptions.RequestException(msg)
    return ret


def get_ntp(ibmc):
    """
    Function:
        Get NTP configuration
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/10/12 21:13
    """
    ibmc.log_info("Start get NTP configuration resource info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Get the return result of the redfish interface
    request_result_json = get_ntp_request(ibmc)
    # Write the result to a file
    result = {
        "ServiceEnabled": request_result_json.get("ServiceEnabled"),
        "ServerAuthenticationEnabled": request_result_json.get(
            "ServerAuthenticationEnabled"),
        "PreferredNtpServer": request_result_json.get("PreferredNtpServer"),
        "AlternateNtpServer": request_result_json.get("AlternateNtpServer"),
        "NtpAddressOrigin": request_result_json.get("NtpAddressOrigin"),
        "NTPKeyStatus": request_result_json.get("NTPKeyStatus"),
        "MinPollingInterval": request_result_json.get("MinPollingInterval"),
        "MaxPollingInterval": request_result_json.get("MaxPollingInterval")
    }

    # Update ret
    ret['result'] = True
    ret[
        'msg'] = "Get NTP configuration resource info successful! The NTP configuration resource info is: %s" % \
                 str(result)

    ibmc.log_info("Get NTP configuration resource info successful!")
    return ret


def get_ntp_request(ibmc):
    """
    Function:
        Get the return result of the redfish interface
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        request_result_json : result of the redfish interface
    Raises:
        Get NTP configuration resource info failed!
    Date: 2019/10/28 21:26
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # URL of the NTP service
    url = ibmc.manager_uri + "/NtpService"

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the NTP configuration resource information through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            msg = "Get NTP configuration resource info failed! The error code is: %s, " \
                  "The error info is: %s \n" % (
                      str(request_code), str(request_result.json()))
            ibmc.log_error(msg)
            raise Exception(msg)
        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error(
            "Get NTP configuration resource failed! The error info is: %s \n" % str(
                e))
        raise requests.exceptions.RequestException(
            "Get NTP configuration resource failed!")

    return request_result_json
