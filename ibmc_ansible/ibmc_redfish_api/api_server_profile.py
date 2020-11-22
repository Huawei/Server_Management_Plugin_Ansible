#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail
import time

from ibmc_ansible.utils import set_result

# Max waiting time
WAIT_TASK_TIME = 600


def export_profile(ibmc, file_path):
    """
    Args:
            file_path            (str): file path for export server profile
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/Actions/Oem/Huawei/Manager.ExportConfiguration" % ibmc.manager_uri
    token = ibmc.get_token()

    headers = {'Content-Type': 'application/json', 'X-Auth-Token': token}
    payload = {'Type': 'URI', 'Content': file_path}

    try:
        r = ibmc.request('POST', resource=uri,
                         headers=headers, data=payload, tmout=60)
    except Exception as e:
        r = None
        ibmc.log.info("export server profile failed: %s" % str(e))
        raise

    return r


def import_profile(ibmc, file_path):
    """
    Args:
            file_path            (str):   file path for import server profile
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/Actions/Oem/Huawei/Manager.ImportConfiguration" % ibmc.manager_uri
    token = ibmc.get_token()

    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    payload = {"Type": "URI", "Content": file_path}

    try:
        r = ibmc.request('POST', resource=uri,
                         headers=headers, data=payload, tmout=60)
    except Exception as e:
        r = None
        ibmc.log_info("import server profile failed: %s" % str(e))
        raise
    return r


def server_profile(ibmc, file_path, command):
    """
    Args:
            file_path            (str):   file path for export or import server profile
            command              (str):  export or import
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    rets = {'result': True, 'msg': ''}
    token = ibmc.get_token()

    if command.upper() == "IMPORT":
        r = import_profile(ibmc, file_path)
    elif command.upper() == "EXPORT":
        r = export_profile(ibmc, file_path)
    else:
        log_msg = "unknown command:%s; please check the server_profile.yml " % str(
            command)
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    cnt = -1
    try:
        code = r.status_code
        data = r.json()
        if code == 202:
            taskid = data['Id']
            for cnt in range(WAIT_TASK_TIME):
                time.sleep(1)
                ret = ibmc.get_task_info(taskid)
                if ret is not None and ret.status_code == 200:
                    code = ret.status_code
                    data = ret.json()
                elif ret is not None:
                    ibmc.log_info(
                        "code is: %s ,may be there are disconnect,you should wait for a moment!" % str(ret.status_code))
                    continue
                else:
                    ibmc.log_info(
                        "ret is None,may be there are disconnect,you should wait for a moment!")
                    continue

                ret = data[u'TaskState']
                percent = data[u'Oem'][u'Huawei'][u'TaskPercentage']
                ibmc.log_info("status: %s percent: %s" % (ret, str(percent)))
                if ret == 'Running':
                    time.sleep(1)
                    continue
                elif ret == 'OK' or ret == 'Completed' or percent == '100%':
                    log_msg = "%s: %s successful! " % (
                        command, file_path.split("/")[-1])
                    set_result(ibmc.log_info, log_msg, True, rets)
                    return rets
                else:
                    log_msg = "%s: %s failed! " % (
                        command, file_path.split("/")[-1])
                    set_result(ibmc.log_error, log_msg, False, rets)
                    return rets

            if cnt == (WAIT_TASK_TIME - 1):
                log_msg = " %s : %s  get task result timeout " % (
                    command, file_path)
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
        else:
            log_msg = " %s profile %s failed! the error code is %s" % (
                command, file_path, str(code))
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets

    except Exception as e:
        log_msg = "%s profile exception! %s" % (command, str(e))
        set_result(ibmc.log_error, log_msg, False, rets)
    return rets
