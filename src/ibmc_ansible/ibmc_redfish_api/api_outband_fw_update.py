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


def update_api(ibmc, file_path, protocol=None):
    """
       Args:
               file_path            (str):   path of the firmware
               protocol              (str): protocol of the file server
       Returns:
           None
       Raises:
           None
       Examples:
           None
       Author: xwh
       Date: 10/19/2019
    """
    uri = "%s/UpdateService/Actions/UpdateService.SimpleUpdate" % ibmc.root_uri
    token = ibmc.get_token()

    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    if protocol is not None:
        protocol = protocol
        playload = {"ImageURI": file_path, "TransferProtocol": protocol}
    else:
        playload = {"ImageURI": file_path}
    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=playload, tmout=60)
    except Exception as e:
        r = None
        ibmc.log_error("update exception: %s" % (str(e)))
        raise Exception("update exception %s" % str(e))
    return r


def update_fw(ibmc, file_path, protocol=None):
    """
       Args:
               file_path            (str):   path of the firmware
               protocol              (str): protocol of the file server
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
    try:
        if protocol is not None:
            ret = update_api(ibmc, file_path, protocol)
        else:
            ret = update_api(ibmc, file_path)
        ibmc.log_info("ret:%s" % (str(ret)))
        code = ret.status_code
        data = ret.json()
        ibmc.log_info("code:%s" % (str(code)))
        if code == 202:
            taskid = data['Id']
            while 1:
                time.sleep(1)
                ret = ibmc.get_task_info(taskid)
                if ret is not None and ret.status_code == 200:
                    code = ret.status_code
                    data = ret.json()
                elif ret is not None:
                    ibmc.log_info(
                        "code is :%s may be there are disconnect,you should wait for a moment!\n" % ret.status_code)
                    continue
                else:
                    ibmc.log_info(
                        "ret is None,may be there are disconnect,you should wait for a moment!\n")
                    continue
                ret = data[u'TaskState']
                percent = data[u'Oem'][u'Huawei'][u'TaskPercentage']
                percent = percent if percent else 0
                ibmc.log_info("status:%s percent:%s" % (ret, str(percent)))
                if ret == 'Running':
                    time.sleep(1)
                    continue
                elif ret == 'OK' or ret == 'Completed' or percent == '100%':
                    log_msg = "update %s successful! \n" % (file_path.split("/")[-1])
                    set_result(ibmc.log_info, log_msg, True, rets)
                    break
                else:
                    log_msg = " update %s failed! \n" % (file_path.split("/")[-1])
                    set_result(ibmc.log_error, log_msg, False, rets)
                    break

        else:
            log_msg = "update failed: %s" % (data[u'error'][u'@Message.ExtendedInfo'][0][u'Message'])
            set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    except Exception as e:
        ibmc.log_error("update failed! exception is: %s" % (str(e)))
        raise
