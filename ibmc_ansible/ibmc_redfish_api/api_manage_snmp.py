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

from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import set_result
from ibmc_ansible.ibmc_redfish_api.api_manage_account import get_account_id

TRAP_VERSION_DICT = {
    "v1": "V1",
    "v2c": "V2C",
    "v3": "V3"
}

TRAP_MODE_DICT = {
    "oid": "OID",
    "eventcode": "EventCode",
    "precisealarm": "PreciseAlarm"
}

HOST_IDENTITY_DICT = {
    "boardsn": "BoardSN",
    "productassettag": "ProductAssetTag",
    "hostname": "HostName"
}

ALARM_SEVERITY_DICT = {
    "critical": "Critical",
    "major": "Major",
    "minor": "Minor",
    "normal": "Normal"
}

# Maximum community name length
MAX_COMMUNITY_LEN = 18

# Minimum port number
MIN_PORT = 1
# Maximum port number
MAX_PORT = 65535


def set_snmp_trap(ibmc, snmp_info):
    """
    Function:
        Set SNMP trap resource properties
    Args:
        ibmc : Class that contains basic information about iBMC
        snmp_info : User-set SNMP trap information
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Set SNMP trap resource properties failed!
    Date: 2019/10/12 17:21
    """
    ibmc.log_info("Start set SNMP trap resource properties...")

    # Obtain user-configured SNMP trap information
    community = snmp_info.get('community')
    service_enabled = snmp_info.get('service_enabled')
    trap_version = snmp_info.get('trap_version')
    trap_v3_user = snmp_info.get('trap_v3_user')
    trap_server_list = snmp_info.get('trap_servers')

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Initialize payload
    trap_payload = {}

    # Whether trap is enabled, The optional parameters are: true or false
    if service_enabled is not None:
        if service_enabled is True:
            trap_payload["ServiceEnabled"] = True
        elif service_enabled is False:
            trap_payload["ServiceEnabled"] = False
        else:
            log_msg = 'The service enabled is incorrect, It should be True or False'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # SNMPv3 user name, valid only for trap version is V3
    if trap_v3_user is not None:
        # Verify trap v3 user name
        account_id = get_account_id(ibmc, trap_v3_user)
        if account_id is None:
            log_msg = "The trap v3 username: %s does not exist" % trap_v3_user
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        trap_payload["TrapV3User"] = trap_v3_user

    # Trap mode, The optional parameters are: "OID", "EventCode" or "PreciseAlarm"
    # 1.It is not allowed to set the community when TrapVersion is V3
    # 2.The CommunityName cannot contain spaces
    # 3.The length of the community name is 1-18.
    if community is not None:
        community_res = check_community(ibmc, trap_version, community)
        if community_res.get("result") is False:
            return community_res

        trap_payload["CommunityName"] = community

    items = (('trap_version', "TrapVersion", TRAP_VERSION_DICT),
             ('trap_mode', "TrapMode", TRAP_MODE_DICT),
             ('trap_server_identity', "TrapServerIdentity", HOST_IDENTITY_DICT),
             ('alarm_severity', "AlarmSeverity", ALARM_SEVERITY_DICT))
    for item, item_name, item_dict in items:
        check_result = check_item(ibmc, snmp_info, item, item_dict)
        if isinstance(check_result, dict):
            if check_result.get("result") is False:
                return check_result
        else:
            trap_payload[item_name] = check_result

    # Trap Server, supports setting the server enable status (true, false),
    # server address (IPv4, IPv6, and domain name), and server port (1-65535)
    if trap_server_list is not None:
        if not isinstance(trap_server_list, list):
            log_msg = 'The trap servers format is incorrect, please set it in the set_snmp_trap.yml file'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        server_list = []
        for trap_server in trap_server_list:
            server_dict = get_server_dict(ibmc, trap_server)
            if server_dict.get("result") is not None:
                return server_dict

            # Store Trap server information in an array in order
            server_list.append(server_dict)

        trap_payload["TrapServer"] = server_list

    # If the input parameter is empty, prompt the user to enter the correct parameter in the yml file
    if trap_payload == {}:
        log_msg = 'The parameter is empty, please enter the correct parameter in the set_snmp_trap.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    ret = set_snmp_trap_request(ibmc, trap_payload)
    return ret


def check_item(ibmc, snmp_info, item, item_dict):
    """
    Function:
        Set SNMP trap resource properties
    Args:
        ibmc : Class that contains basic information about iBMC
        snmp_info : User-set SNMP trap information
        item : Validation item
        item_dict : Value range of item
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Set SNMP trap resource properties failed!
    Date: 2019/10/12 17:21
    """
    ret = {'result': True, 'msg': ''}
    item_value = snmp_info.get(item)
    if item_value:
        item_value = item_dict.get(str(item_value).lower())
        if item_value in item_dict.values():
            return item_value
        else:
            log_msg = 'The trap version is incorrect, It should be %s' % item_dict
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    return ret


def set_snmp_trap_request(ibmc, trap_payload):
    """
    Function:
        Send request for setting SNMP trap
    Args:
        ibmc :   Class that contains basic information about iBMC
        trap_payload : request body
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Set SNMP trap resource properties failed!
    Date: 2019/10/12 17:21
    """
    ret = {'result': True, 'msg': ''}
    payload = {"SnmpTrapNotification": trap_payload}
    # URL of the SNMP service
    url = ibmc.manager_uri + "/SnmpService"
    # Obtain token
    token = ibmc.bmc_token
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token,
               'If-Match': etag}
    try:
        # Modify SNMP trap resource properties by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set SNMP trap resource properties successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set SNMP trap resource properties failed! " \
                      "The error code is: %s, The error info is: %s." \
                      % (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("Set SNMP trap resource properties failed! "
                       "The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Set SNMP trap resource properties failed! "
                                                   "The error info is: %s" % str(e))
    return ret


def get_server_dict(ibmc, trap_server):
    """
    Function:
        Send request for setting SNMP trap
    Args:
        ibmc :   Class that contains basic information about iBMC
        trap_server : User-specified server
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Set SNMP trap resource properties failed!
    Date: 2019/10/12 17:21
    """
    server_dict = {}
    ret = {'result': True, 'msg': ''}
    if trap_server:
        trap_server_enabled = trap_server.get("trap_server_enabled")
        trap_server_address = trap_server.get("trap_server_address")
        trap_server_port = trap_server.get("trap_server_port")

        # Verify the validity of the Trap server enabled
        if trap_server_enabled is not None:
            trap_server_enabled = str(trap_server_enabled).lower()
            if trap_server_enabled == "true":
                server_dict["Enabled"] = True
            elif trap_server_enabled == "false":
                server_dict["Enabled"] = False
            else:
                log_msg = 'The TrapServer/Enabled is incorrect, It should be True or False'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if trap_server_address:
            server_dict["TrapServerAddress"] = trap_server_address

        # Verify the validity of the Trap server port
        try:
            if trap_server_port is None:
                return server_dict
            # Verify trap_server_port is an integer
            if not isinstance(trap_server_port, int):
                log_msg = 'The TrapServer/Port must be an integer'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            if trap_server_port < MIN_PORT or trap_server_port > MAX_PORT:
                log_msg = 'The TrapServer/Port is incorrect, It should be a integer from %s to %s' % \
                            (str(MIN_PORT), str(MAX_PORT))
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            else:
                server_dict["TrapServerPort"] = trap_server_port
        except ValueError as e:
            log_msg = 'The TrapServer/Port is illegal! The error info is: %s \n' % str(e)
            ibmc.log_error(log_msg)
            raise ValueError(log_msg)
    return server_dict


def check_community(ibmc, trap_version, community):
    """
    Function:
        Send request for setting SNMP trap
    Args:
        ibmc : Class that contains basic information about iBMC
        trap_version : User_set snmp trap version
        community : User-set community
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Set SNMP trap resource properties failed!
    Date: 2019/10/12 17:21
    """
    ret = {'result': True, 'msg': ''}
    try:
        if trap_version == "V3":
            log_msg = 'It is not allowed to set the community name when trap version is V3.'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if len(community) > MAX_COMMUNITY_LEN:
            log_msg = 'Invalid length of the community name, the length of the community cannot exceed %s.' % \
                      str(MAX_COMMUNITY_LEN)
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if community.find(" ") != -1:
            log_msg = 'The community name cannot contain spaces.'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        ibmc.log_error(
            'The community name is illegal! The error info is: %s \n' % str(e))
        raise ValueError(
            'The community name is illegal! The error info is: %s' % str(e))

    return ret


def get_snmp_trap(ibmc):
    """

    Function:
        Get SNMP trap resource info
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
    ibmc.log_info("Start get SNMP trap resource info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # File to save SNMP trap resource information
    file_name = os.path.join(IBMC_REPORT_PATH, "snmp_trap", str(ibmc.ip) + "_SNMPTrapInfo.json")

    # Get the return result of the redfish interface
    request_result_json = get_snmp_request(ibmc)

    # Write the result to a file
    result = {
        "SnmpTrapNotification": request_result_json.get("SnmpTrapNotification")
    }
    write_result(ibmc, file_name, result)

    # Update ret
    ret['result'] = True
    ret['msg'] = "Get SNMP trap resource info successful! " \
                 "For more detail information please refer to %s" % file_name

    ibmc.log_info("Get SNMP trap resource info successful!")
    return ret


def get_snmp_request(ibmc):
    """
    Function:
        Get the return result of the redfish interface
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        SNMP request info
    Raises:
        Get SNMP resource info failed!
    Date: 2019/10/29 21:47
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # URL of the SNMP service
    url = ibmc.manager_uri + "/SnmpService"

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the SNMP resource information through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get SNMP resource info failed! The error code is: %s, "
                           "The error info is: %s \n" % (str(request_code), str(request_result.json())))
            raise Exception("Get SNMP resource info failed! The error code is: %s, "
                            "The error info is: %s." % (str(request_code), str(request_result.json())))
        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error("Get SNMP resource info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Get SNMP resource info failed!")

    return request_result_json
