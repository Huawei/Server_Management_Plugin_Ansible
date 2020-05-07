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

from ibmc_ansible.utils import set_result, IBMC_REPORT_PATH, write_result
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
              ibmc                    (class):    Class that contains basic information about iBMC
              snmp_info               (dict):     User-set SNMP trap information
    Returns:
         {"result": True, "msg": "Set SNMP trap resource properties successful!"}
    Raises:
         Set SNMP trap resource properties failed!
    Examples:
         None
    Author:
    Date: 2019/10/12 17:21
    """
    ibmc.log_info("Start set SNMP trap resource properties...")

    # Obtain user-configured SNMP trap information
    community = snmp_info.get('community')
    service_enabled = snmp_info.get('service_enabled')
    trap_version = snmp_info.get('trap_version')
    trap_v3_user = snmp_info.get('trap_v3_user')
    trap_mode = snmp_info.get('trap_mode')
    trap_server_identity = snmp_info.get('trap_server_identity')
    alarm_severity = snmp_info.get('alarm_severity')
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

    # Trap version, The optional parameters are: "V1", "V2C" or "V3"
    if trap_version:
        trap_version = TRAP_VERSION_DICT.get(str(trap_version).lower())
        if trap_version in TRAP_VERSION_DICT.values():
            trap_payload["TrapVersion"] = trap_version
        else:
            log_msg = 'The trap version is incorrect, It should be "V1", "V2C" or "V3"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # SNMPv3 user name, valid only for trap version is V3
    if trap_v3_user:
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
    if community:
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
            ibmc.log_error('The community name is illegal! The error info is: %s \n' % str(e))
            raise ValueError('The community name is illegal! The error info is: %s' % str(e))

        trap_payload["CommunityName"] = community

    # Trap mode, The optional parameters are: "OID", "EventCode" or "PreciseAlarm"
    if trap_mode:
        trap_mode = TRAP_MODE_DICT.get(str(trap_mode).lower())
        if trap_mode in TRAP_MODE_DICT.values():
            trap_payload["TrapMode"] = trap_mode
        else:
            log_msg = 'The trap mode is incorrect, It should be "OID", "EventCode" or "PreciseAlarm"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Host identifier, The optional parameters are: "BoardSN", "ProductAssetTag" or "HostName"
    # This parameter is valid only when TrapMode is OID or PreciseAlarm
    if trap_server_identity:
        trap_server_identity = HOST_IDENTITY_DICT.get(str(trap_server_identity).lower())
        if trap_server_identity in HOST_IDENTITY_DICT.values():
            trap_payload["TrapServerIdentity"] = trap_server_identity
        else:
            log_msg = 'The trap server identity is incorrect, It should be "BoardSN", "ProductAssetTag" or "HostName"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Severity levels of the alarm to be sent, The optional parameters are: "Critical", "Major", "Minor" or "Normal"
    if alarm_severity:
        alarm_severity = ALARM_SEVERITY_DICT.get(str(alarm_severity).lower())
        if alarm_severity in ALARM_SEVERITY_DICT.values():
            trap_payload["AlarmSeverity"] = alarm_severity
        else:
            log_msg = 'The alarm severity is incorrect, It should be "Critical", "Major", "Minor" or "Normal"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Trap Server, supports setting the server enable status (true, false),
    # server address (IPv4, IPv6, and domain name), and server port (1-65535)
    if trap_server_list:
        if not isinstance(trap_server_list, list):
            log_msg = 'The trap servers format is incorrect, please set it in the set_snmp_trap.yml file'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        server_list = []
        for trap_server in trap_server_list:
            server_dict = {}
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
                    if trap_server_port is not None:
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
                    ibmc.log_error('The TrapServer/Port is illegal! The error info is: %s \n' % str(e))
                    raise ValueError('The TrapServer/Port is illegal! The error info is: %s' % str(e))

            # Store Trap server information in an array in order
            server_list.append(server_dict)

        trap_payload["TrapServer"] = server_list

    # If the input parameter is empty, prompt the user to enter the correct parameter in the yml file
    if trap_payload == {}:
        log_msg = 'The parameter is empty, please enter the correct parameter in the set_snmp_trap.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    payload = {"SnmpTrapNotification": trap_payload}

    # URL of the SNMP service
    url = ibmc.manager_uri + "/SnmpService"

    # Obtain token
    token = ibmc.bmc_token

    # Obtain etag
    etag = ibmc.get_etag(url)

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

    try:
        # Modify SNMP trap resource properties by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set SNMP trap resource properties successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set SNMP trap resource properties failed! The error code is: %s, " \
                      "The error info is: %s." % (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("Set SNMP trap resource properties failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException(
            "Set SNMP trap resource properties failed! The error info is: %s" % str(e))

    return ret


def get_snmp_trap(ibmc):
    """

    Function:
        Get SNMP trap resource info
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        {"result": True, "msg": "Get SNMP trap resource info successful!"}
    Raises:
        None
    Examples:
        None
    Author:
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
    ret['msg'] = "Get SNMP trap resource info successful! For more detail information please refer to %s" % file_name

    ibmc.log_info("Get SNMP trap resource info successful!")
    return ret


def get_snmp_request(ibmc):
    """

    Function:
        Get the return result of the redfish interface
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
        SNMP request info
    Raises:
        Get SNMP resource info failed!
    Examples:
        None
    Author:
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
