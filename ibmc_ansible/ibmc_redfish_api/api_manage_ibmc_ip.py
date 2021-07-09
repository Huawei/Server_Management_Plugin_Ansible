#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import requests

from ibmc_ansible.utils import validata_ipv4_in_gateway
from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import validate_ipv4
from ibmc_ansible.utils import validate_ipv6

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

    # Get the current IP version
    oem_info = ibmc.oem_info
    request_result_json = get_ibmc_ip_request(ibmc)
    try:
        current_ip = {}
        curr_ip_version = request_result_json["Oem"][oem_info]["IPVersion"]
        current_ip["curr_ip_version"] = curr_ip_version
    except Exception as e:
        log_error = "Get iBMC current ip failed! The error info is: %s \n" % str(e)
        ibmc.log_error(log_error)
        raise Exception(log_error)

    # Check whether the user configuration is valid in advance.
    ip_info_check = check_information(ibmc, ip_info, current_ip)
    if not ip_info_check.get('result'):
        return ip_info_check

    # Obtain user-configured IP information
    ip_version = ip_info.get('ip_version')
    ipv4_addr = ip_info.get('ipv4_addr')
    ipv6_addr = ip_info.get('ipv6_addr')
    ipv6_gateway = ip_info.get('ipv6_gateway')

    # Verify the legality of the IPv4 address, IPv6 address and IPv6 gateway
    verify_result = validate_ip_address(ibmc, ipv4_address_list=ipv4_addr,
                                        ipv6_address_list=ipv6_addr,
                                        ipv6_gateway=ipv6_gateway)
    if not verify_result.get('result'):
        return verify_result

    # Initialize payload
    ip_addr_payload = {}
    if ipv4_addr:
        ip_addr_payload['IPv4Addresses'] = convert_ipv4_addr(ipv4_addr)
    if ipv6_addr:
        ip_addr_payload['IPv6Addresses'] = convert_ipv6_addr(ipv6_addr)
    if ipv6_gateway:
        ip_addr_payload['IPv6DefaultGateway'] = ipv6_gateway

    ret = set_ip_result(ibmc, ip_addr_payload, ip_version, curr_ip_version)

    return ret


def set_ip_result(ibmc, ip_address_payload, ip_version, current_ip_version):
    """
    Function:
        Set the IP address and return the setting result.
    Args:
        ibmc: Class that contains basic information about iBMC
        ip_address_payload: IP address to be set
        ip_version: IP_version information to be set
        current_ip_version: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    oem_info = ibmc.oem_info
    # parameter in the yml file
    prepare_change_version = False

    if ip_address_payload:
        # Prepare for changing IP_version and IP_addr at the same time.
        if ip_version is not None and ip_version != current_ip_version:
            if current_ip_version != "IPv4AndIPv6":
                prepare_ret = prepare_ip_version(ibmc)
                if not prepare_ret.get("result"):
                    return prepare_ret

                prepare_change_version = True
        # Set iBMC IP address
        log_massage = "ethernet interface"
        ret = set_ibmc_ip_request(ibmc, ip_address_payload, log_massage)

    # If the setting fails, restore IP_version.
    if not ret.get('result'):
        if prepare_change_version:
            log_info = "Failed to change IP_addr. Restore IP_version."
            ibmc.log_info(log_info)
            restore_res = restore_ip_version(ibmc, current_ip_version)
            if not restore_res.get('result'):
                log_error = "Failed to change IP_addr! Failed to restore IP_version!"
                set_result(ibmc.log_error, log_error, False, ret)
                return ret
        return ret

    # Set IP version
    if not ip_version:
        pass
    elif ip_version == "IPv4AndIPv6" and prepare_change_version:
        version_msg = "Set ip_version successful"
        set_result(ibmc.log_info, version_msg, True, ret)
    else:
        ip_version_payload = {"Oem": {oem_info: {"IPVersion": ip_version}}}
        ret = set_ibmc_ip_request(ibmc, ip_version_payload,
                                  log_massage="ip_version")

        if not ret.get('result'):
            return ret

    if ip_version and ip_address_payload:
        log_msg = "Set ip_addr successful! Set ip_version successful!"
        set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def prepare_ip_version(ibmc):
    """
    Function:
        To ensure successful setting, set ip_version to IPv4AndIPv6.
    Args:
        ibmc: Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    oem_info = ibmc.oem_info
    log_info = "Change IP_Version to IPv4AndIPv6 and " \
               "prepare for the change of ip_addr."
    ibmc.log_info(log_info)
    ip_prepare_version = "IPv4AndIPv6"
    payload_prepare = {
        "Oem": {oem_info: {"IPVersion": ip_prepare_version}}}
    ret = set_ibmc_ip_request(ibmc, payload_prepare, log_massage="praparing")
    return ret


def restore_ip_version(ibmc, current_ip_version):
    """
    Function:
        If the setting fails, restore ip_version to the current state.
    Args:
        ibmc: Class that contains basic information about iBMC
        current_ip_version: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    oem_info = ibmc.oem_info
    restore_payload = {"Oem": {oem_info: {"IPVersion": current_ip_version}}}
    ret = set_ibmc_ip_request(ibmc, restore_payload, "ip_version restoring")

    return ret


def check_information(ibmc, ip_information, current_ip):
    """
    Function:
        Check whether the settings transferred by the user are proper.
    Args:
        ibmc: Class that contains basic information about iBMC
        ip_information: IP address set by the user
        current_ip: Current IP address on the BMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {'result': True, 'msg': ''}
    log_error = None

    # Obtain user-configured IP information
    ip_version = ip_information.get('ip_version')
    ip_version = IP_DICT.get(str(ip_version).lower())
    ipv4_addr = ip_information.get('ipv4_addr')
    ipv6_addr = ip_information.get('ipv6_addr')
    ipv6_gateway = ip_information.get('ipv6_gateway')
    current_version = current_ip.get("curr_ip_version")

    # If the input parameter is empty, prompt the user to enter the correct
    param = (ip_version, ipv4_addr, ipv6_addr, ipv6_gateway)
    if not any(param):
        log_msg = 'The input parameter is empty, please enter the correct ' \
                  'parameter in the set_ibmc_ip.yml file. '
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # If IP_version is not modified, ensure that the current IP_version supports the modified IP_addr.
    if ip_version is None:
        if current_version == "IPv4" and (ipv6_addr or ipv6_gateway):
            log_error = "The current IP_version is IPv4 enabled. " \
                        "The ipv6_addr or ipv6_gateway cannot be set." \
                        " Please reconfigure the setting."
        elif current_version == "IPv6" and ipv4_addr:
            log_error = "The current IP_version is IPv6 enabled. " \
                        "The ipv4_addr cannot be set." \
                        " Please reconfigure the setting."

    # Ensure that the modified ip_version supports the modified ip_addr.
    elif ip_version == "IPv4":
        if ipv6_addr or ipv6_gateway:
            log_error = "When IP_version is set to IPv4, the setting of ipv6_addr " \
                        "or ipv6_gateway becomes invalid and cannot continue." \
                        " Please reconfigure the setting."
        elif (ipv4_addr is None) and (current_version == "IPv6"):
            log_error = "The current IPv4_addr does not exist. Please configure an IPv4_addr. "

    elif ip_version == "IPv6":
        if ipv4_addr:
            log_error = "When IP_version is set to IPv6, the setting of ipv4_addr " \
                        " becomes invalid and cannot continue." \
                        " Please reconfigure the setting."
        elif (ipv6_addr is None) and (current_version == "IPv4"):
            log_error = "The current IPv6_addr does not exist. Please configure an IPv6_addr. "

    elif ip_version != "IPv4AndIPv6":
        log_error = 'The ip version is incorrect, it shoule be "IPv4", "IPv6" or "IPv4AndIPv6".'

    if log_error is not None:
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    log_info = "Check user configuration successful!"
    set_result(ibmc.log_info, log_info, True, ret)
    return ret


def set_ibmc_ip_request(ibmc, payload, log_massage):
    """
    Function:
        Sends an IP address setting request to the BMC.
    Args:
        ibmc: Class that contains basic information about iBMC
        payload: Request body
        log_massage: Set content description.
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    # Obtain ethernet interface_id
    ethernet_interface_id = get_ethernet_interface_id(ibmc)
    if not ethernet_interface_id:
        ret['result'] = False
        ret['msg'] = 'Set iBMC ethernet interface info failed!'
        return ret
    # URL of the iBMC network port information
    url = "%s/EthernetInterfaces/%s" % (ibmc.manager_uri, ethernet_interface_id)
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token,
               'If-Match': etag}
    try:
        # Modify iBMC ip version by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=10)
    except Exception as e:
        log_msg = "Set iBMC %s failed! The error info is: %s \n" % (log_massage, str(e))
        ibmc.log_error(log_msg)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    # Obtain the error code
    request_code = request_result.status_code
    if request_code == 200:
        log_msg = "Set iBMC %s successful!" % log_massage
        set_result(ibmc.log_info, log_msg, True, ret)
        return ret
    else:
        log_msg = "Set iBMC %s failed! The error code is: %s, " \
                  "The error info is: %s." % (log_massage, str(request_code),
                                              str(request_result.json()))
        set_result(ibmc.log_error, log_msg, False, ret)
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
    result_file = os.path.join(IBMC_REPORT_PATH, "ibmc_ip",
                               "%s_iBMCIPInfo.json" % str(ibmc.ip))

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
    ret['msg'] = "Get iBMC ethernet interface info successful! " \
                 "For more detail information please refer to %s." % result_file

    ibmc.log_info("Get iBMC ethernet interface info successful!")
    return ret


def get_ibmc_ip_request(ibmc):
    """
    Function:
        Get the return result of the redfish interface
    Args:
              ibmc            :   Class that contains basic information about iBMC
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
        ibmc.log_error("Get iBMC ethernet interface info failed!")
        raise Exception("Get iBMC ethernet interface info failed!")

    # URL of the iBMC network port information
    url = "%s/EthernetInterfaces/%s" % (ibmc.manager_uri, ethernet_interface_id)

    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the network port information of the iBMC through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            error = "Get iBMC ethernet interface info failed!" \
                    "The error code is: %s. The error info is: %s"\
                    % (str(request_code), str(request_result.json()))
            ibmc.log_error(error)
            raise Exception(error)
        else:
            request_result_json = request_result.json()
    except Exception as e:
        error = "Get iBMC ethernet interface info failed! " \
                "The error info is: %s" % str(e)
        ibmc.log_error(error)
        raise requests.exceptions.RequestException(error)

    return request_result_json


def validate_ip_address(ibmc, ipv4_address_list=None, ipv6_address_list=None, ipv6_gateway=None):
    """
    Function:
        Verify the legality of the IP address
    Args:
        ibmc:
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
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    # if IPv4 address info is not None
    if ipv4_address_list:
        # Determine the data type of IPv4 address info
        if not isinstance(ipv4_address_list, list):
            log_msg = "The IPv4 address format is incorrect, please set it in the set_ibmc_ip.yml file."
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        for ipv4 in ipv4_address_list:
            log_msg = check_ipv4(ipv4)
            if log_msg is not None:
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    # if IPv6 address info is not None
    if ipv6_address_list:
        # Determine the data type of IPv6 address info
        if not isinstance(ipv6_address_list, list):
            log_msg = "The IPv6 address format is incorrect, please set it in the set_ibmc_ip.yml file."
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        for ipv6 in ipv6_address_list:
            log_msg = check_ipv6(ipv6, ipv6_gateway)
            if log_msg is not None:
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    # if IPv6 gateway is not None
    if ipv6_gateway:
        log_msg = None
        # Determine the data type of IPv6 gateway
        if not isinstance(ipv6_gateway, str):
            log_msg = "The IPv6 gateway format is incorrect, please set it in the set_ibmc_ip.yml file"
        elif not validate_ipv6(ipv6_gateway):
            log_msg = "The IPv6 gateway is invalid."

        if log_msg is not None:
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    log_msg = "Verify the IP address successful"
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def check_ipv6(ipv6, ipv6_gateway):
    log_msg = None
    ipv6_address = ipv6.get("address")
    ipv6_prefix_length = ipv6.get("prefix_length")
    ipv6_address_origin = ipv6.get("address_origin")
    # Verify address
    if not validate_ipv6(ipv6_address):
        log_msg = "The IPv6 address is invalid."
    # Verify prefix_length
    if ipv6_prefix_length is not None:
        # Verify ipv6_prefix_length is an integer
        if not isinstance(ipv6_prefix_length, int):
            log_msg = "The IPv6 prefix length is invalid, it must be a integer."
        try:
            if ipv6_prefix_length < MIN_PREFIX_LEN or ipv6_prefix_length > MAX_PREFIX_LEN:
                log_msg = "The IPv6 prefix length is invalid, the value ranges from %s to %s." % (
                    str(MIN_PREFIX_LEN), str(MAX_PREFIX_LEN))
        except ValueError:
            log_msg = "The IPv6 prefix length is invalid."
    # Verify address origin
    if ipv6_address_origin:
        if ipv6_address_origin.lower() == "static":
            pass
        # When the IPv6 address origin is DHCPv6:
        # 1.The IPV6 address and prefix length cannot be set at the same time;
        # 2.Gateway setting is not allowed.
        elif ipv6_address_origin.lower() == "dhcpv6":
            if ipv6_address or ipv6_prefix_length:
                log_msg = "The request for IPv6Addresses modification failed " \
                          "because the value of IPv6Addresses/AddressOrigin is DHCPv6."
            elif ipv6_gateway:
                log_msg = "The request for the property IPv6DefaultGateway modification failed " \
                          "because the address is in DHCPv6 mode."
        else:
            log_msg = 'The IPv6 address origin is incorrect, it shoule be "Static" or "DHCPv6".'
    return log_msg


def check_ipv4(ipv4):
    log_msg = None
    ipv4_address = ipv4.get("address")
    ipv4_subnet_mask = ipv4.get("subnet_mask")
    ipv4_gateway = ipv4.get("gateway")
    ipv4_address_origin = ipv4.get("address_origin")
    # Verity address, subnet_mask, gateway
    if not validate_ipv4(ipv4_address):
        log_msg = "The IPv4 address is invalid."
    elif not validate_ipv4(ipv4_subnet_mask):
        log_msg = "The IPv4 subnet mask is invalid."
    elif not validate_ipv4(ipv4_gateway):
        log_msg = "The IPv4 gateway is invalid."
    elif ipv4_address_origin:
        # When the IPv4 address origin is Static, the IP address and gateway are on the same network segment.
        if ipv4_address_origin.lower() == "static":
            if not validata_ipv4_in_gateway(ipv4_address, ipv4_gateway,
                                            ipv4_subnet_mask):
                log_msg = "The IPv4 address and gateway are not on the same network segment."
        # When the IPv4 address origin is DHCP, cannot set the IPv4 address, subnet mask, and gateway.
        elif ipv4_address_origin.lower() == "dhcp":
            if ipv4_address or ipv4_subnet_mask or ipv4_gateway:
                log_msg = "The request for IPv4Addresses modification failed " \
                          "because the value of IPv4Addresses/AddressOrigin is DHCP."
        else:
            log_msg = 'The IPv4 address origin is incorrect, it shoule be "Static" or "DHCP".'
    return log_msg


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
            ibmc.log_error("Get iBMC ethernet interface id failed! "
                           "The error code is: %s. The error info is: %s." %
                           (str(request_result.status_code), str(request_result.json())))
            return ethernet_interface_id

        # Obtain ethernet interface id
        odata_id = data["Members"][0]["@odata.id"]
        ethernet_interface_id = odata_id.split('/')[-1]
        ibmc.log_info("Get iBMC ethernet interface id successful!")
    except Exception as e:
        ibmc.log_error(
            "Get iBMC ethernet interface id failed! The error info is: %s." % str(
                e))
    return ethernet_interface_id


def convert_ipv4_addr(ipv4_address_list):
    """

    Function:
        Convert IPv4 address format
    Args:
              ipv4_address_list            (list):   IPv4 address list
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
    for ipv4_addr in ipv4_address_list:
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
            result_dict["AddressOrigin"] = IP_DICT.get(
                str(address_origin).lower())
        result_list.append(result_dict)
    return result_list


def convert_ipv6_addr(ipv6_address_list):
    """

    Function:
        Convert IPv6 address format
    Args:
              ipv6_address_list            (list):   IPv6 address list
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
    for ipv6_addr in ipv6_address_list:
        result_dict = {}
        address = ipv6_addr.get("address")
        prefix_length = ipv6_addr.get("prefix_length")
        address_origin = ipv6_addr.get("address_origin")
        if address:
            result_dict["Address"] = address
        if prefix_length:
            result_dict["PrefixLength"] = prefix_length
        if address_origin:
            result_dict["AddressOrigin"] = IP_DICT.get(
                str(address_origin).lower())
        result_list.append(result_dict)
    return result_list
