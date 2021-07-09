#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
import time

from ibmc_ansible.utils import set_result
from ibmc_ansible.ibmc_redfish_api.api_manage_file import download_file_request
from ibmc_ansible.ibmc_redfish_api.api_manage_raid import get_task_status
from ibmc_ansible.utils import IBMC_REPORT_PATH

# File server type
FILE_SERVER = ("sftp", "https", "nfs", "cifs", "scp")
# File server information to be configured
FILE_SERVER_INFO = ("file_server_ip", "file_server_user", "file_server_pswd")
# Waiting time for start
START_TIME = 5
# Waiting time for next loop
SLEEP_TIME = {"SEL": 5, "IBMC": 15}
# Waiting time for getting results
GET_RESULT_TIME = {"SEL": 40, "IBMC": 60}
# Command delivery timed out.
TIME_OUT = 30


def collect_log(ibmc, save_location, file_name, log_type):
    """
    Function:
        Collecting Maintenance Information About All Modules of a Board
    Args:
        ibmc : Class that contains basic information about iBMC
        save_location : a dict to describe log storage information.
        file_name : Log file storage path and file name
        log_type: Collect SEL log or IBMC log
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
    log_type = log_type.upper()

    # Collecting Logs
    oem_info = ibmc.oem_info
    if log_type == "SEL":
        get_id_res = get_log_id(ibmc)
        if not get_id_res.get("result"):
            return get_id_res
        log_id = get_id_res.get("msg")
        root_url = "https://%s" % ibmc.ip

        url = "%s%s/Actions/Oem/%s/LogService.CollectSel" % (root_url, log_id, oem_info)
    else:
        url = "%s/Actions/Oem/%s/Manager.Dump" % (ibmc.manager_uri, oem_info)

    if not file_name:
        log_error = 'Collect %s logs failed! The file_name parameter must ' \
                    'contain the name of the log file' % log_type
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    # get path for storing collected log files
    log_path_result = get_log_path(ibmc, save_location, file_name, log_type)
    if not log_path_result.get('result'):
        return log_path_result

    log_path = log_path_result.get('msg')
    file_server_type = save_location.get("save_mode")

    if file_server_type is None:
        file_server_type = "local"
    file_server_type = file_server_type.lower()

    request_result = collect_log_request(ibmc, log_path, url, log_type)

    if not request_result.get('result'):
        return request_result

    if file_server_type in FILE_SERVER:
        log_info = "%s %s logs have been save as %s on %s server " \
                   % (request_result.get('msg'), log_type, file_name, file_server_type)
        set_result(ibmc.log_info, log_info, True, ret)
        return ret

    # Download logs to the local host.
    path, name = os.path.split(file_name)
    # Set Default Path
    if not path:
        default_path = "collect_%s_log" % log_type
        file_path = os.path.join(IBMC_REPORT_PATH, default_path)
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        file_name = os.path.join(file_path, name)

    down_log_result = download_file_request(ibmc, name, file_name, file_type="log")
    if not down_log_result.get('result'):
        log_error = 'Collect %s logs failed! The error info is: %s' \
                    % (log_type, down_log_result.get('msg'))
        set_result(ibmc.log_error, log_error, False, ret)
    else:
        log_info = 'Collect %s logs successfully! Logs have been saved as %s' % (log_type, file_name)
        set_result(ibmc.log_info, log_info, True, ret)
    return ret


def get_log_path(ibmc, save_location, file_name, log_type):
    """
    Function:
        Parse and combine the log file storage path.
    Args:
        ibmc : Class that contains basic information about iBMC
        save_location : a dict to describe log storage information.
        file_name : Log file storage path and file name
        log_type : Collected log name
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
    if not file_name.startswith('/'):
        file_name = "/%s" % file_name
    path, name = os.path.split(file_name)
    if not name:
        log_error = 'Collect %s logs failed! The file_name parameter must ' \
                    'contain the name of the log file' % log_type
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    file_server_type = save_location.get("save_mode")
    if file_server_type is None:
        file_server_type = "local"
    file_server_type = file_server_type.lower()

    if file_server_type in FILE_SERVER:
        # Storage through a remote file server
        file_server_ip = save_location.get("file_server_ip")
        file_server_user = save_location.get("file_server_user")
        file_server_pswd = save_location.get("file_server_pswd")
        if file_server_pswd and file_server_user:
            log_path = "%s://%s:%s@%s%s" % (file_server_type, file_server_user,
                                            file_server_pswd, file_server_ip,
                                            file_name)
        else:
            log_path = "%s://%s%s" % (file_server_type, file_server_ip, file_name)

    elif file_server_type == "local":
        # Save to the local host , Check whether the local path exists.
        if not os.path.exists(path):
            log_error = 'Collect %s logs failed! The %s is not exist!' % (log_type, path)
            set_result(ibmc.log_error, log_error, False, ret)
            return ret
        log_path = "/tmp/web/%s" % name

    else:
        log_error = "The save_mode is wrong, please chose form 'sftp', " \
                    "'https', 'nfs', 'cifs', 'scp' or 'local'!"
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    ret['msg'] = log_path
    return ret


def collect_log_request(ibmc, log_path, url, log_type):
    """
    Function:
        Send request to collect logs
    Args:
        ibmc : Class that contains basic information about iBMC
        log_path : Log file storage path and file name
        url: Redfish API for collect logs
        log_type : Collected log name
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
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token}
    payload = {"Type": "URI", "Content": log_path}

    # send request to collect logss
    try:
        request_result = ibmc.request('POST', resource=url, headers=headers,
                                      data=payload, tmout=TIME_OUT)
        request_code = request_result.status_code
        request_result_json = request_result.json()
    except Exception as e:
        error_msg = "Collect %s logs failed! The error info is: %s \n" \
                    % (log_type, str(e))
        set_result(ibmc.log_error, error_msg, False, ret)
        return ret

    if request_code != 202:
        log_error = "Collect %s logs failed! The error code is: %s, " \
                    "The error info is: %s." \
                    % (log_type, str(request_code), str(request_result_json))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    task_url = request_result_json.get("@odata.id")
    ibmc.log_info("Collecting %s logs..." % log_type)
    ret = wait_collect(ibmc, task_url, log_type)

    return ret


def wait_collect(ibmc, task_url, log_type):
    """
    Function:
        wait task start for
    Args:
        ibmc : Class that contains basic information about iBMC
        task_url : url of task
        log_type : Collected log name
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ret = {'result': True, 'msg': ''}
    # Wait for task start
    time.sleep(START_TIME)

    request_time = GET_RESULT_TIME.get(log_type)
    sleep_time = SLEEP_TIME.get(log_type)
    for loop_time in range(0, request_time):
        # Get task result
        try:
            task_result = get_task_status(ibmc, task_url)
        except Exception as e:
            log_error = "Get task status exception, " \
                        "The error info is: %s, continue..." % str(e)
            set_result(ibmc.log_error, log_error, False, ret)
            return ret

        loop_time += 1
        if task_result[0].find("Successful") != -1:
            log_msg = "Collect %s logs successfully!" % log_type
            set_result(ibmc.log_info, log_msg, True, ret)
            return ret

        elif task_result[-1].find("failed") != -1 or task_result[0].find("Exception") != -1:
            log_error = "Collect %s logs failed! %s" % (log_type, task_result[-1])
            set_result(ibmc.log_error, log_error, False, ret)
            return ret
        else:
            time.sleep(sleep_time)
    # Collect time out
    log_msg = "Collect %s logs failed! Collection timed out." % log_type
    set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def get_log_id(ibmc):
    """
    Function:
        Indicates the ID of a log file dynamically obtained.
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2021/6/30 18:04
    """
    ret = {'result': True, 'msg': ''}

    url = "%s/LogServices" % ibmc.system_uri
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token
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
        res_info = request_result.json()
    except Exception as e:
        log_error = "Get log id failed! The error info is %s" % e
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    if request_code != 200:
        log_error = "Get log id failed! The error info is %s" % res_info
        set_result(ibmc.log_error, log_error, False, ret)
    else:
        log_id = res_info.get("Members")[0].get("@odata.id")
        ret["msg"] = log_id
    return ret


def clear_sel_log(ibmc):
    """
    Function:
        Clear SEL logs
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
    ibmc.log_info("Start to clear SEL logs...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    get_id_res = get_log_id(ibmc)
    if not get_id_res.get("result"):
        return get_id_res
    log_id = get_id_res.get("msg")
    root_url = "https://%s" % ibmc.ip
    url = "%s%s/Actions/LogService.ClearLog" % (root_url, log_id)

    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    try:
        # Obtain the BIOS resource information through the GET method
        request_result = ibmc.request('POST', resource=url,
                                      headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
    except Exception as e:
        log_error = "Clear SEL logs failed! The error info is: %s \n" % str(e)
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    if request_code != 200:
        log_error = "Clear SEL logs failed! The error code is: %s, " \
                    "The error info is: %s \n" % \
                    (str(request_code), str(request_result.json()))
        set_result(ibmc.log_error, log_error, False, ret)
    else:
        log_info = "Clear SEL logs successfully!"
        set_result(ibmc.log_info, log_info, True, ret)

    return ret
