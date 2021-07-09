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

from ibmc_ansible.ibmc_redfish_api.api_manage_file import upload_file, \
    download_file_request
from ibmc_ansible.utils import set_result

# Max waiting time
WAIT_TASK_TIME = 200


def import_profile(ibmc, file_path, local):
    """
    Function:
        Importing BIOS, BMC, and RAID Controller Configurations
    Args:
        ibmc: Class that contains basic information about iBMC
        file_path: Path of the file to be imported
        local: Import from local
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {'result': True, 'msg': ''}
    save_path, file_name = os.path.split(file_path)
    if local:
        upload_file_ret = upload_file(ibmc, file_path)
        if upload_file_ret.get('result'):
            file_path = os.path.join("/tmp/web", file_name)
        else:
            return upload_file_ret

    oem_info = ibmc.oem_info
    uri = "%s/Actions/Oem/%s/Manager.ImportConfiguration" % (ibmc.manager_uri, oem_info)
    token = ibmc.get_token()
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': token}
    payload = {'Type': 'URI', 'Content': file_path}

    try:
        request_result = ibmc.request('POST', resource=uri,
                                      headers=headers, data=payload, tmout=60)
    except Exception as e:
        log_error = "Import server profile failed: %s" % str(e)
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    log_info = "Send request to import profile succeeded, please waitting for task finish."
    ibmc.log_info(log_info)
    request_code = request_result.status_code
    request_json = request_result.json()
    if request_code == 202:
        ret['result'] = True
        ret['msg'] = request_result.json()
    else:
        log_error = "Import server profile failed, The status code is %s. " \
                    "The error info is: %s." % (request_code, str(request_json))
        set_result(ibmc.log_error, log_error, False, ret)

    return ret


def export_profile(ibmc, file_path, local):
    """
    Function:
        Export BIOS, BMC, and RAID Controller Configurations
    Args:
        ibmc: Class that contains basic information about iBMC
        file_path: Path to save the file
        local: Export to local
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {'result': True, 'msg': ''}
    save_path, file_name = os.path.split(file_path)
    if local:
        file_path = os.path.join("/tmp/web", file_name)

    oem_info = ibmc.oem_info
    uri = "%s/Actions/Oem/%s/Manager.ExportConfiguration" % (ibmc.manager_uri, oem_info)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {"Type": "URI", "Content": file_path}

    try:
        request_result = ibmc.request('POST', resource=uri,
                                      headers=headers, data=payload, tmout=60)
    except Exception as e:
        log_error = "Export server profile failed: %s" % str(e)
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    request_code = request_result.status_code
    request_json = request_result.json()

    if request_code != 202:
        log_error = "Export profile failed! The status code is %s. " \
                    "The error info is %s" % (request_code, str(request_json))
        set_result(ibmc.log_error, log_error, False, ret)
    else:
        ret['result'] = True
        ret['msg'] = request_json

    return ret


def server_profile(ibmc, file_path, command, local):
    """
    Function:
        Export or import BIOS, BMC, and RAID Controller Configurations
    Args:
        ibmc: Class that contains basic information about iBMC
        file_path: Path to save the file
        command: Export or import
        local: Import from local
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {'result': True, 'msg': ''}
    save_path, file_name = os.path.split(file_path)

    # Select Import or Export.
    if command.upper() == "IMPORT":
        request_ret = import_profile(ibmc, file_path, local)
    elif command.upper() == "EXPORT":
        request_ret = export_profile(ibmc, file_path, local)
    else:
        log_msg = "unknown command:%s" % str(command)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    if not request_ret.get('result'):
        return request_ret

    data = request_ret.get('msg')
    transfer_result = wait_task(ibmc, data, command, file_path)
    if not transfer_result.get('result') or \
            command.upper() == "IMPORT" or not local:
        return transfer_result

    download_result = download_file_request(ibmc, file_name, file_path, file_type="profile")
    if not download_result.get('result'):
        log_error = "Export profile failed! The error info is %s" % download_result.get("msg")
        set_result(ibmc.log_error, log_error, False, ret)
    else:
        log_info = "Export profile successful! Profile have been saved as %s" % file_path
        set_result(ibmc.log_info, log_info, True, ret)
    return ret


def wait_task(ibmc, data, command, file_path):
    """
    Function:
        Obtaining the File Transfer Result
    Args:
        ibmc: Class that contains basic information about iBMC
        data: Information returned after sending request
        command: Export or import
        file_path: Path to save the file
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    rets = {'result': True, 'msg': ''}
    save_path, file_name = os.path.split(file_path)
    cnt = -1
    task_id = data.get('Id')
    oem_info = ibmc.oem_info

    try:
        for cnt in range(WAIT_TASK_TIME):
            time.sleep(3)
            task_ret = ibmc.get_task_info(task_id)

            if task_ret.status_code != 200:
                ibmc.log_info("code is: %s ,may be there are disconnect, "
                              "you should wait for a moment!" % str(task_ret.status_code))
                continue

            data = task_ret.json()
            ret = data[u'TaskState']
            percent = data[u'Oem'][oem_info][u'TaskPercentage']
            ibmc.log_info("status: %s percent: %s" % (ret, str(percent)))

            if ret == 'Running':
                time.sleep(1)
                continue
            elif ret == 'OK' or ret == 'Completed' or percent == '100%':
                log_msg = "%s: %s successful! " % (command, file_name)
                set_result(ibmc.log_info, log_msg, True, rets)
                return rets
            else:
                log_msg = "%s: %s failed! The error info is %s " % \
                          (command, file_name, str(data['Messages']['Message']))
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets

        if cnt == (WAIT_TASK_TIME - 1):
            log_msg = " %s : %s failed! Get task result timeout " % (
                command, file_name)
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets

    except Exception as e:
        log_msg = "%s profile exception! %s" % (command, str(e))
        set_result(ibmc.log_error, log_msg, False, rets)

    return rets
