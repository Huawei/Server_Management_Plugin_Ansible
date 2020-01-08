#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import requests

from ibmc_ansible.utils import set_result, IBMC_REPORT_PATH, write_result, validate_ipv4, validate_ipv6, \
    validata_ipv4_in_gateway

IP_DICT = {
    "ipv4andipv6": "IPv4AndIPv6",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "static": "Static",
    "dhcp": "DHCP",
    "dhcpv6": "DHCPv6"
}

# Minimum perfix length
MIN_PREFIX_LEN = 0
# Maximum perfix length
MAX_PREFIX_LEN = 128


def set_ibmc_ip(ibmc, ip_info):
    """

    Function:
        Modify iBMC network port information.
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
              ip_info           (dict):    User-set IP information
    Returns:
        {"result": True, "msg": "Set iBMC ethernet interface info successful!"}
    Raises:
        Set ibmc ethernet interface info failed!
    Examples:
        None
    Author:
    Date: 2019/9/23 21:21
    """
    ibmc.log_info("Start set iBMC ip...")

    # Obtain user-configured IP information
    ip_version = ip_info.get('ip_version')
    ipv4_addr = ip_info.get('ipv4_addr')
    ipv6_addr = ip_info.get('ipv6_addr')
    ipv6_gateway = ip_info.get('ipv6_gateway')

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Initialize payload
    ip_addr_payload = {}
    ip_version_payload = {}

    # Obtain ethernet interface_id
    ethernet_interface_id = get_ethernet_interface_id(ibmc)
    if not ethernet_interface_id:
        ret['result'] = False
        ret['msg'] = 'Set iBMC ethernet interface info failed!'
        return ret

    # URL of the iBMC network port information
    url = "%s/EthernetInterfaces/%s" % (ibmc.manager_uri, ethernet_interface_id)

    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Set iBMC IP version, The optional parameters are: "IPv4", "IPv6", "IPv4AndIPv6"
    if ip_version:
        ip_version = IP_DICT.get(str(ip_version).lower())
        if ip_version in ["IPv4AndIPv6", "IPv4", "IPv6"]:
            ip_version_payload["Oem"] = {"Huawei": {"IPVersion": ip_version}}
        else:
            log_msg = 'The ip version is incorrect, it shoule be "IPv4", "IPv6" or "IPv4AndIPv6".'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        # Obtain etag
        etag = ibmc.get_etag(url)
        # Initialize headers
        headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

        try:
            # Modify iBMC ip version by PATCH method
            request_result = ibmc.request('PATCH', resource=url, headers=headers, data=ip_version_payload, tmout=10)
        except Exception as e:
            ibmc.log_error("Set iBMC ip version failed! The error info is: %s \n" % str(e))
            raise requests.exceptions.RequestException("Set iBMC ip version failed! The error info is: %s" % str(e))
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set iBMC ip version successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set iBMC ip version failed! The error code is: %s, " \
                      "The error info is: %s." % (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    if ipv4_addr or ipv6_addr or ipv6_gateway:
        # Get the current IP version
        request_result_json = get_ibmc_ip_request(ibmc)
        try:
            ip_version = request_result_json["Oem"]["Huawei"]["IPVersion"]
            ibmc.log_info("Get iBMC current ip version successful!")
        except Exception as e:
            ibmc.log_error("Get iBMC current ip version failed! The error info is: %s \n" % str(e))
            raise Exception("Get iBMC current ip version failed! The error info is: %s" % str(e))

        # Get the user's IP configuration for different IP version
        if ip_version == "IPv4AndIPv6":
            # Verify the legality of the IPv4 address, IPv6 address and IPv6 gateway
            verify_result, verify_message = validate_ipaddr(ipv4addr_list=ipv4_addr, ipv6addr_list=ipv6_addr,
                                                            ipv6gateway=ipv6_gateway)
            if verify_result is True:
                if ipv4_addr:
                    ip_addr_payload['IPv4Addresses'] = convert_ipv4_addr(ipv4_addr)
                if ipv6_addr:
                    ip_addr_payload['IPv6Addresses'] = convert_ipv6_addr(ipv6_addr)
                if ipv6_gateway:
                    ip_addr_payload['IPv6DefaultGateway'] = ipv6_gateway
            else:
                set_result(ibmc.log_error, verify_message, False, ret)
                return ret

        elif ip_version == "IPv4":
            if not ipv4_addr:
                log_msg = 'Failed to modify IPv6Addresses information because IPv6 is disabled.'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            # Verify the legality of the IPv4 address
            verify_result, verify_message = validate_ipaddr(ipv4addr_list=ipv4_addr)
            if verify_result is True:
                ip_addr_payload['IPv4Addresses'] = convert_ipv4_addr(ipv4_addr)
            else:
                set_result(ibmc.log_error, verify_message, False, ret)
                return ret

        elif ip_version == "IPv6":
            if not (ipv6_addr or ipv6_gateway):
                log_msg = 'Failed to modify IPv4Addresses information because IPv4 is disabled.'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            # Verify the legality of the IPv4 address IPv6 address and IPv6 gateway
            verify_result, verify_message = validate_ipaddr(ipv6addr_list=ipv6_addr, ipv6gateway=ipv6_gateway)
            if verify_result is True:
                if ipv6_addr:
                    ip_addr_payload['IPv6Addresses'] = convert_ipv6_addr(ipv6_addr)
                if ipv6_gateway:
                    ip_addr_payload['IPv6DefaultGateway'] = ipv6_gateway
            else:
                set_result(ibmc.log_error, verify_message, False, ret)
                return ret

        else:
            log_msg = 'The current ip version is: %s, which is incorrect. ' \
                      'It shoule be "IPv4", "IPv6" or "IPv4AndIPv6".' % ip_version
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # If the input parameter is empty, prompt the user to enter the correct parameter in the yml file
    payload = dict(ip_version_payload, **ip_addr_payload)
    if payload == {}:
        log_msg = 'The input parameter is empty, please enter the correct parameter in the set_ibmc_ip.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Set iBMC IP address
    if ip_addr_payload:
        # Obtain etag
        etag = ibmc.get_etag(url)
        # Initialize headers
        headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

        try:
            # Modify iBMC ip address by PATCH method
            request_result = ibmc.request('PATCH', resource=url, headers=headers, data=ip_addr_payload, tmout=10)
            # Obtain the error code
            request_code = request_result.status_code
            if request_code == 200:
                log_msg = "Set iBMC ethernet interface info successful!"
                set_result(ibmc.log_info, log_msg, True, ret)
            else:
                log_msg = "Set iBMC ethernet interface info failed! The error code is: %s, " \
                          "The error info is: %s." % (str(request_code), str(request_result.json()))
                set_result(ibmc.log_error, log_msg, False, ret)
        except Exception as e:
            ibmc.log_error("Set iBMC ethernet interface info failed! The error info is: %s \n" % str(e))
            raise requests.exceptions.RequestException("Set iBMC ethernet interface info failed! "
                                                       "The error info is: %s." % str(e))

    return ret


def get_ibmc_ip(ibmc):
    """

    Function:
        Query network port information of the manager resource.
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        {"result": True, "msg": "Get iBMC ethernet interface info successful!"}
    Raises:
        None
    Examples:
         None
    Author:
    Date: 2019/9/24 11:48
    """
    ibmc.log_info("Start get iBMC ip...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # File to save iBMC network port information
    result_file = os.path.join(IBMC_REPORT_PATH, "ibmc_ip", str(ibmc.ip) + "_iBMCIPInfo.json")

    # Get the return result of the redfish interface
    request_result_json = get_ibmc_ip_request(ibmc)

    # Write the result to a file
    result = {
        "IPv4Addresses": request_result_json.get("IPv4Addresses"),
        "IPv6Addresses": request_result_json.get("IPv6Addresses"),
        "IPv6DefaultGateway": request_result_json.get("IPv6DefaultGateway"),
        "PermanentMACAddress": request_result_json.get("PermanentMACAddress"),
        "Oem": request_result_json.get("Oem"),
        "IPv6StaticAddresses": request_result_json.get("IPv6StaticAddresses")
    }
    write_result(ibmc, result_file, result)

    # Update ret
    ret['result'] = True
    ret['msg'] = "Get iBMC ethernet interface info successful! For more detail information please refer to %s." \
                 % result_file

    ibmc.log_info("Get iBMC ethernet interface info successful!")
    return ret


def get_ibmc_ip_request(ibmc):
    """

    Function:
        Get the return result of the redfish interface
    Args:
              ibmc            (str):   Class that contains basic information about iBMC
    Returns:
        result of the redfish interface
    Raises:
        Get iBMC ethernet interface info failed!
    Examples:
        None
    Author:
    Date: 2019/10/26 10:55
    """
    # Get ethernet interface id
    ethernet_interface_id = get_ethernet_interface_id(ibmc)
    if ethernet_interface_id is None:
        raise Exception("Get iBMC ethernet interface info failed!")

    # URL of the iBMC network port information
    url = ibmc.manager_uri + "/EthernetInterfaces/" + ethernet_interface_id

    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the network port information of the iBMC through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get iBMC ethernet interface info failed! The error code is: %s, "
                           "The error info is: %s \n" % (str(request_code), str(request_result.json())))
            raise Exception("Get iBMC ethernet interface info failed! The error code is: %s, "
                            "The error info is: %s" % (str(request_code), str(request_result.json())))
        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error("Get iBMC ethernet interface info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException(
            "Get iBMC ethernet interface info failed! The error info is: %s" % str(e))

    return request_result_json


def validate_ipaddr(ipv4addr_list=None, ipv6addr_list=None, ipv6gateway=None):
    """

    Function:
        Verify the legality of the IP address
    Args:
              ipv4addr_list            (list):   IPv4 address info
              ipv6addr_list            (list):   IPv6 address info
              ipv6gateway              (str):    IPv6 gateway
    Returns:
        True or error info
    Raises:
        The IPv4 address is invalid. or
        The IPv6 address is invalid. or
        The IPv6 gateway is invalid.
    Examples:
        None
    Author:
    Date: 2019/10/8 15:55
    """

    # if IPv4 address info is not None
    if ipv4addr_list:
        # Determine the data type of IPv4 address info
        if not isinstance(ipv4addr_list, list):
            return False, "The IPv4 address format is incorrect, please set it in the set_ibmc_ip.yml file."
        for ipv4 in ipv4addr_list:
            ipv4_address = ipv4.get("address")
            ipv4_subnet_mask = ipv4.get("subnet_mask")
            ipv4_gateway = ipv4.get("gateway")
            ipv4_address_origin = ipv4.get("address_origin")

            # Verity address, subnet_mask, gateway
            if not validate_ipv4(ipv4_address):
                return False, "The IPv4 address is invalid."
            if not validate_ipv4(ipv4_subnet_mask):
                return False, "The IPv4 subnet mask is invalid."
            if not validate_ipv4(ipv4_gateway):
                return False, "The IPv4 gateway is invalid."

            if ipv4_address_origin:
                # When the IPv4 address origin is Static, the IP address and gateway are on the same network segment.
                if ipv4_address_origin.lower() == "static":
                    if not validata_ipv4_in_gateway(ipv4_address, ipv4_gateway, ipv4_subnet_mask):
                        return False, "The IPv4 address and gateway are not on the same network segment."
                # When the IPv4 address origin is DHCP, cannot set the IPv4 address, subnet mask, and gateway.
                elif ipv4_address_origin.lower() == "dhcp":
                    if ipv4_address or ipv4_subnet_mask or ipv4_gateway:
                        return False, "The request for IPv4Addresses modification failed " \
                                      "because the value of IPv4Addresses/AddressOrigin is DHCP."
                else:
                    return False, 'The IPv4 address origin is incorrect, it shoule be "Static" or "DHCP".'

    # if IPv6 address info is not None
    if ipv6addr_list:
        # Determine the data type of IPv6 address info
        if not isinstance(ipv6addr_list, list):
            return False, "The IPv6 address format is incorrect, please set it in the set_ibmc_ip.yml file."
        for ipv6 in ipv6addr_list:
            ipv6_address = ipv6.get("address")
            ipv6_prefix_length = ipv6.get("prefix_length")
            ipv6_address_origin = ipv6.get("address_origin")

            # Verify address
            if not validate_ipv6(ipv6_address):
                return False, "The IPv6 address is invalid."

            # Verify prefix_length
            if ipv6_prefix_length is not None:
                # Verify ipv6_prefix_length is an integer
                if not isinstance(ipv6_prefix_length, int):
                    return False, "The IPv6 prefix length is invalid, it must be a integer."
                try:
                    if ipv6_prefix_length < MIN_PREFIX_LEN or ipv6_prefix_length > MAX_PREFIX_LEN:
                        return False, "The IPv6 prefix length is invalid, the value ranges from %s to %s." % (
                            str(MIN_PREFIX_LEN), str(MAX_PREFIX_LEN))
                except ValueError:
                    return False, "The IPv6 prefix length is invalid."

            # Verify address origin
            if ipv6_address_origin:
                if ipv6_address_origin.lower() == "static":
                    pass
                # When the IPv6 address origin is DHCPv6:
                # 1.The IPV6 address and prefix length cannot be set at the same time;
                # 2.Gateway setting is not allowed.
                elif ipv6_address_origin.lower() == "dhcpv6":
                    if ipv6_address or ipv6_prefix_length:
                        return False, "The request for IPv6Addresses modification failed " \
                                      "because the value of IPv6Addresses/AddressOrigin is DHCPv6."
                    if ipv6gateway:
                        return False, "The request for the property IPv6DefaultGateway modification failed " \
                                      "because the address is in DHCPv6 mode."
                else:
                    return False, 'The IPv6 address origin is incorrect, it shoule be "Static" or "DHCPv6".'

    # if IPv6 gateway is not None
    if ipv6gateway:
        # Determine the data type of IPv6 gateway
        if not isinstance(ipv6gateway, str):
            return False, "The IPv6 gateway format is incorrect, please set it in the set_ibmc_ip.yml file"
        if not validate_ipv6(ipv6gateway):
            return False, "The IPv6 gateway is invalid."

    return True, "Verify the IP address successful"


def get_ethernet_interface_id(ibmc):
    """

    Function:
        Query network port collection information of the manager resource
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        ethernet interface id
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/9 19:29
    """

    # Initialize ethernet interface id
    ethernet_interface_id = None

    # URL of the network port collection information
    url = ibmc.manager_uri + "/EthernetInterfaces"

    try:
        # Obtain the network port collection information of the manager resource through the GET method
        request_result = ibmc.request('GET', resource=url, tmout=10)

        if request_result.status_code == 200:
            data = request_result.json()
        else:
            ibmc.log_error("Get iBMC ethernet interface id failed! The error code is: %s, "
                           "The error info is: %s." % (str(request_result.status_code), str(request_result.json())))
            return ethernet_interface_id

        # Obtain ethernet interface id
        odata_id = data["Members"][0]["@odata.id"]
        ethernet_interface_id = odata_id.split('/')[-1]
        ibmc.log_info("Get iBMC ethernet interface id successful!")
    except Exception as e:
        ibmc.log_error("Get iBMC ethernet interface id failed! The error info is: %s." % str(e))
    return ethernet_interface_id


def convert_ipv4_addr(ipv4_addr_list):
    """

    Function:
        Convert IPv4 address format
    Args:
              ipv4_addr_list            (list):   IPv4 address list
    Returns:
        list
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/26 22:25
    """
    result_list = []
    for ipv4_addr in ipv4_addr_list:
        result_dict = {}
        address = ipv4_addr.get("address")
        gateway = ipv4_addr.get("gateway")
        subnet_mask = ipv4_addr.get("subnet_mask")
        address_origin = ipv4_addr.get("address_origin")
        if address:
            result_dict["Address"] = address
        if gateway:
            result_dict["Gateway"] = gateway
        if subnet_mask:
            result_dict["SubnetMask"] = subnet_mask
        if address_origin:
            result_dict["AddressOrigin"] = IP_DICT.get(str(address_origin).lower())
        result_list.append(result_dict)
    return result_list


def convert_ipv6_addr(ipv6_addr_list):
    """

    Function:
        Convert IPv6 address format
    Args:
              ipv6_addr_list            (list):   IPv6 address list
    Returns:
        list
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/26 22:32
    """
    result_list = []
    for ipv6_addr in ipv6_addr_list:
        result_dict = {}
        address = ipv6_addr.get("address")
        prefix_length = ipv6_addr.get("prefix_length")
        address_origin = ipv6_addr.get("address_origin")
        if address:
            result_dict["Address"] = address
        if prefix_length:
            result_dict["PrefixLength"] = prefix_length
        if address_origin:
            result_dict["AddressOrigin"] = IP_DICT.get(str(address_origin).lower())
        result_list.append(result_dict)
    return result_list
