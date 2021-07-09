#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import time
import os

from ibmc_ansible.utils import set_result
from ibmc_ansible.ibmc_redfish_api.api_manage_file import upload_file

# File server type
FILE_SERVER = ("HTTPS", "SCP", "SFTP", "CIFS", "NFS")


def update_api(ibmc, file_path, protocol=None):
    """
    Function:
        send request to update firmware
    Args:
        ibmc : Class that contains basic information about iBMC
        file_path : path of the firmware
        protocol : protocol of the file server
    Returns:
        r : result of request
    Raises:
        update exception
    Date: 10/19/2019
    """
    uri = "%s/UpdateService/Actions/UpdateService.SimpleUpdate" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Check whether the firmware package is saved on the file server.
    if protocol is not None:
        payload = {"ImageURI": file_path, "TransferProtocol": protocol}
    else:
        payload = {"ImageURI": file_path}

    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=payload,
                         tmout=60)
        return r
    except Exception as e:
        log_err = "update exception: %s" % (str(e))
        ibmc.log_error(log_err)
        raise Exception(log_err)


def update_fw(ibmc, file_path, protocol=None, local=False):
    """
    Function:
        Out_band firmware upgrade
    Args:
        ibmc : Class that contains basic information about iBMC
        file_path : path of the firmware
        protocol : protocol of the file server
        local
    Returns:
        rets : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        update failed
    Date: 10/19/2019
    """
    # Initialize return information
    rets = {'result': True, 'msg': ''}

    # Uploading a Local Firmware Package
    if local:
        upload_file_ret = upload_file(ibmc, file_path)
        if upload_file_ret.get('result') is False:
            return upload_file_ret
        file_name = file_path.split("/")[-1]
        file_path = os.path.join("/tmp/web", file_name)

    if protocol is not None:
        if protocol not in FILE_SERVER:
            log_msg = "The protocol error, please choose from [HTTPS, SCP, SFTP, CIFS, NFS] \n"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets

    # Sending a Firmware Upgrade Request
    try:
        if protocol:
            ret = update_api(ibmc, file_path, protocol)
        else:
            ret = update_api(ibmc, file_path)
        ibmc.log_info("ret:%s" % (str(ret)))
        code = ret.status_code
        data = ret.json()
        ibmc.log_info("code:%s" % (str(code)))
        if code != 202:
            log_msg = "update failed: %s" % (data[u'error'][u'@Message.ExtendedInfo'][0][u'Message'])
            set_result(ibmc.log_error, log_msg, False, rets)
        else:
            wait_task(ibmc, data, file_path, rets)
        return rets

    except Exception as e:
        ibmc.log_error("update failed! exception is: %s" % (str(e)))
        raise


def wait_task(ibmc, data, file_path, rets):
    """
    Function:
        Out_band firmware upgrade
    Args:
        ibmc : Class that contains basic information about iBMC
        file_path : path of the firmware
        data : information from request
        rets: result of last step
    Returns:
        None
    Raises:
        None
    Date: 10/19/2019
    """
    task_id = data.get('Id')
    oem_info = ibmc.oem_info
    while 1:
        time.sleep(3)
        ret = ibmc.get_task_info(task_id)

        # Check whether the connection is successful.
        if ret is not None and ret.status_code == 200:
            data = ret.json()
        elif ret is not None:
            ibmc.log_info("code is :%s may be there are disconnect, "
                          "you should wait for a moment!\n" % ret.status_code)
            continue
        else:
            ibmc.log_info("ret is None,may be there are disconnect, "
                          "you should wait for a moment!\n")
            continue

        ret = data[u'TaskState']
        percent = data[u'Oem'][oem_info][u'TaskPercentage']
        percent = percent if percent else 0
        ibmc.log_info("status:%s percent:%s" % (ret, str(percent)))

        # Check the completion status of the current task.
        if ret == 'Running':
            time.sleep(1)
            continue
        elif ret == 'OK' or ret == 'Completed' or percent == '100%':
            log_msg = "update %s successful! \n" % (file_path.split("/")[-1])
            set_result(ibmc.log_info, log_msg, True, rets)
            break
        else:
            reason = data[u'Messages'][u'Message']
            log_msg = " update %s failed! The failed info is %s \n" \
                      % (file_path.split("/")[-1], reason)
            set_result(ibmc.log_error, log_msg, False, rets)
            break
