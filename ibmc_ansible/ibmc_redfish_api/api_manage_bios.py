#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import requests
import os
import time

from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import set_result
from ibmc_ansible.ibmc_redfish_api.api_power_manager import manage_power, \
    get_power_status

# Max Number of Queries, 40 times
Query_TIME = 40


def get_bios_info(ibmc, attribute):
    """
    Function:
        Get bios information
    Args:
        ibmc : Class that contains basic information about iBMC
        attribute : BIOS characteristics specified by the user
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ibmc.log_info("Start get BIOS info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Get the return result of the redfish interface
    request_result_json = get_bios_request(ibmc)

    # Obtains information about a specified BIOS attribute.
    all_bios_res = request_result_json.get("Attributes")
    ibmc.log_info("Parsing BIOS information...")

    failed_list = []
    bios_res = {}
    if not attribute:
        bios_res = all_bios_res
    elif not isinstance(attribute, list):
        log_error = 'The bios_attribute is incorrect, ' \
                    'please set it in the get_bios.yml file'
        set_result(ibmc.log_error, log_error, False, ret)
        return ret
    else:
        for bios_attribute in attribute:
            bios_res[bios_attribute] = all_bios_res.get(bios_attribute)
            if all_bios_res.get(bios_attribute) is None:
                failed_list.append(bios_attribute)

    if failed_list:
        log_error = 'Failed to query %s information.' \
                    'please set it in the get_bios.yml file' % failed_list
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    # File to save BIOS information
    ibmc.log_info("The BIOS information is being stored.")
    name = "%s_BIOSInfo.json" % str(ibmc.ip)
    file_name = os.path.join(IBMC_REPORT_PATH, "bios", name)
    write_result(ibmc, file_name, bios_res)

    report_msg = "Get BIOS information successfully! " \
                 "For more detail information please refer to %s \n" % (
                     file_name)
    ibmc.log_info("Get BIOS information successfully!")
    ret = {'result': True, 'msg': report_msg}
    return ret


def get_bios_request(ibmc):
    """
    Function:
        Send request to get bios information
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # URL of the Bios service
    url = ibmc.system_uri + "/Bios"

    # Initialize headers
    headers = {'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the BIOS resource information through the GET method
        request_result = ibmc.request('GET', resource=url,
                                      headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            error_msg = "Get BIOS info failed! The error code is: %s, " \
                        "The error info is: %s \n" % (
                            str(request_code), str(request_result.json()))
            ibmc.log_error(error_msg)
            raise Exception(error_msg)

        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error(
            "Get BIOS info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Get BIOS info failed!")

    return request_result_json


def set_bios(ibmc, bios_info, immediately):
    """
    Function:
        Set bios
    Args:
        ibmc : Class that contains basic information about iBMC
        bios_info : user set bios information
        immediately : restart the server
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ibmc.log_info("Start to set BIOS configuration resource info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Verify the BIOS content set by the user.
    if not isinstance(bios_info, dict):
        log_msg = 'The attributes format is incorrect, ' \
                  'please set it in the set_bios.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if len(bios_info) == 0:
        log_msg = 'The attributes is null, ' \
                  'please set it in the set_bios.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Obtain the request result.
    payload = {"Attributes": bios_info}
    request_result = set_bios_request(ibmc, payload)
    if not request_result.get('result') or not immediately:
        return request_result

    # Restart the server
    restart_result = restart_server(ibmc)
    if not restart_result.get('result'):
        return restart_result

    ret = verify_configuration(ibmc, bios_info)
    return ret


def restart_server(ibmc):
    """
    Function:
        Restart the server.
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ret = {'result': True, 'msg': ''}
    ibmc.log_info(
        "Restart the server immediately for the configuration to take effect.")

    command = "forcerestart"
    restart_result = manage_power(ibmc, command)
    if not restart_result.get('result'):
        return restart_result

    # get power status
    for _ in range(100):
        time.sleep(2)
        pow_ret = get_power_status(ibmc)
        if "on" in pow_ret.get("msg").lower():
            log_msg = "Server restart successfully"
            set_result(ibmc.log_info, log_msg, True, ret)
            break
    else:
        log_error = "Server restart timed out. Please check the server status later."
        set_result(ibmc.log_error, log_error, False, ret)
    return ret


def verify_configuration(ibmc, bios_info):
    """
    Function:
        Verify that the configuration takes effect after the restart.
    Args:
        ibmc : Class that contains basic information about iBMC
        bios_info : user set bios information
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ret = {'result': True, 'msg': ''}
    ibmc.log_info(
        "Waiting for BIOS settings to take effect.")

    cnt = -1
    try:
        for cnt in range(Query_TIME):
            time.sleep(5)
            setting_ret = get_bios_setting_result(ibmc)
            if not setting_ret.get('result'):
                return setting_ret
            result_msg = setting_ret.get('msg')
            # if Effective, start information verification.
            if result_msg == "Effective":
                break
            if cnt == (Query_TIME - 1):
                log_msg = "BIOS effective timeout, please check later."
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    except Exception as e:
        log_msg = "Get BIOS effective status failed! %s" % (str(e))
        set_result(ibmc.log_error, log_msg, False, ret)

    ibmc.log_info(
        "Verify that the configuration takes effect after the restart.")
    # Obtains the current BIOS configuration information.
    current_bios_json = get_bios_request(ibmc)
    current_bios = current_bios_json.get("Attributes")
    failed_bios_get = {}
    failed_bios_set = {}

    for key, value in bios_info.items():
        if value != current_bios.get(key):
            failed_bios_get[key] = current_bios.get(key)
            failed_bios_set[key] = value

    # Obtain the verification result.
    if failed_bios_get:
        error_msg = "Some BIOS configuration items taken effect failed! " \
                    "User_set bios information is %s. " \
                    "Current bios information is %s" % (
                        failed_bios_set, failed_bios_get)
        set_result(ibmc.log_error, error_msg, False, ret)
    else:
        log_info = "The BIOS configuration has taken effect successful!"
        set_result(ibmc.log_info, log_info, True, ret)

    return ret


def get_bios_setting_result(ibmc):
    """
    Function:
        Querying the Effective Status of BIOS Settings.
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ret = {'result': True, 'msg': ''}
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # URL of the Bios service
    url = ibmc.system_uri + "/Bios/Settings"

    # Initialize headers
    headers = {'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the BIOS effective status information through the GET method
        request_result = ibmc.request('GET', resource=url,
                                      headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            error_msg = "Get BIOS effective status failed! The error code is: %s, " \
                        "The error info is: %s \n" % (
                            str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, error_msg, False, ret)

        else:
            # Parses the response result and obtains the effective status.
            request_result_json = request_result.json()
            effect_status = request_result_json.get('Oem')
            oem_info = ibmc.oem_info
            status = effect_status.get(oem_info).get('EffectiveStatus')
            ret['msg'] = status
    except Exception as e:
        error_msg = "Get BIOS effective status failed! The error info is: %s \n" % str(
            e)
        set_result(ibmc.log_error, error_msg, False, ret)

    return ret


def set_bios_request(ibmc, payload):
    """
    Function:
        send request to set bios configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        payload : request body
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Initialize request information.
    token = ibmc.get_token()
    url = ibmc.system_uri + "/Bios/Settings"
    e_tag = ibmc.get_etag(url)
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token, 'If-Match': e_tag}

    # send request to set bios
    try:
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=10)
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set BIOS configuration resource info successfully! " \
                      "The setting takes effect after the system is restarted."
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set BIOS configuration resource info failed! " \
                      "The error code is: %s, The error info is: %s." % \
                      (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        error_msg = "Set BIOS configuration info failed! The error info is: %s \n" % str(
            e)
        ibmc.log_error(error_msg)
        raise requests.exceptions.RequestException(error_msg)

    return ret


def reset_bios(ibmc, immediately):
    """
    Function:
        send request to reset bios configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        immediately : restart the server
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         Reset BIOS configuration resource info failed!
    Date: 2021/2/22 21:13
    """
    ibmc.log_info("Start to reset BIOS configuration resource info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Initialize request information.
    token = ibmc.get_token()
    url = ibmc.system_uri + "/Bios/Actions/Bios.ResetBios"
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token}
    payload = {}

    # send request to reset bios
    try:
        request_result = ibmc.request('POST', resource=url, headers=headers,
                                      data=payload, tmout=10)
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Reset BIOS configuration resource info successfully!" \
                      "The setting takes effect after the system is restarted."
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Reset BIOS configuration resource info failed! " \
                      "The error code is: %s, The error info is: %s." % \
                      (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    except Exception as e:
        log_error = "Reset BIOS configuration resource info failed! " \
                    "The error info is: %s \n" % str(e)
        ibmc.log_error(log_error)
        raise requests.exceptions.RequestException(log_error)

    # Restart the server
    if immediately:
        restart_ret = restart_server(ibmc)
        if restart_ret.get('result'):
            log_msg = "Reset BIOS configuration resource info successfully! " \
                      "The server has been restarted."
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            ret = restart_ret

    return ret
