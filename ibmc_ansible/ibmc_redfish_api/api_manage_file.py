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
import stat
from requests_toolbelt import MultipartEncoder

from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import IBMC_REPORT_PATH

TIME_OUT = 30


def upload_file(ibmc, file):
    """
    Function:
        Upload files to /bmc/temp
    Args:
        ibmc : Class that contains basic information about iBMC
        file : User-specified file to be transferred
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ibmc.log_info("Start to upload the files...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}
    if not os.path.isfile(file):
        log_error = "Upload file failed! The file %s is incorrect, " \
                    "please reset it." % file
        set_result(ibmc.log_error, log_error, False, ret)
        return ret
    # Initialize request information
    url = "https://%s/redfish/v1/UpdateService/FirmwareInventory" % ibmc.ip
    token = ibmc.get_token()
    filename = file.split("/")[-1]
    with open(file, 'rb') as f:
        # Large files cannot be directly transferred and need to be encoded.
        m = MultipartEncoder(
            fields={'file': (filename, f, 'multipart/form-data')}
        )
        headers = {'X-Auth-Token': token, 'Content-Type': m.content_type}
        try:
            request_result = ibmc.request('POST', resource=url, data=m,
                                          headers=headers, tmout=600)

        except Exception as e:
            log_error = "Send request to upload the file failed! The error info is: %s \n" % str(
                e)
            set_result(ibmc.log_error, log_error, False, ret)
            return ret

    if request_result.status_code != 202:
        log_error = "Send request to upload the file failed! " \
                    "The error code is: %s, The error info is: %s" \
                    % (str(request_result.status_code), str(request_result.json()))
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    log_msg = "Upload file successfully!"
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def download_file(ibmc, bmc_file, local_path=None, change_name=True):
    """
    Function:
        download files from /tmp/web/
    Args:
        ibmc : Class that contains basic information about iBMC
        bmc_file : User-specified file to be download
        local_path :Local path for storing files
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    ibmc.log_info("Start to download the files...")
    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Verify the bmc_file
    if not isinstance(bmc_file, str):
        log_error = "Download file failed! The bmc_file %s is incorrect, the" \
                    " value must be a string. Please reset it." % bmc_file
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    # Verify the local_path
    verify_result = verify_file_path(ibmc, local_path)
    if not verify_result.get('result'):
        return verify_result

    # Set the file name.
    local_path = verify_result.get('msg')
    if change_name:
        date_str = time.strftime("%Y%m%d%H%M%S", time.localtime())
        file_name = '%s_%s_%s' % (str(ibmc.ip), date_str, bmc_file)
    else:
        file_name = bmc_file
    local_file_name = os.path.join(local_path, file_name)

    # Obtaining the download result
    request_result = download_file_request(ibmc, bmc_file, local_file_name)
    if not request_result.get('result'):
        return request_result

    log_msg = "Download file successfully! File saved to %s." % local_file_name
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def verify_file_path(ibmc, local_path=None):
    """
    Function:
        verify local file path
    Args:
        ibmc : Class that contains basic information about iBMC
        local_path :Local path for storing files
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

    # Setting the default save path
    if not local_path:
        local_path = os.path.join(IBMC_REPORT_PATH, "download")
        if not os.path.exists(local_path):
            os.makedirs(local_path)

    # Verify the bmc_file and local_path
    if not os.path.exists(local_path):
        log_error = "Download file failed! The local_path %s is incorrect, the path does not exist." \
                    "Please reset it." % local_path
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    ret['msg'] = local_path
    return ret


def download_file_request(ibmc, bmc_file, local_file_name, file_type=None):
    """
    Function:
        Send request to download files from /tmp/web/
    Args:
        ibmc : Class that contains basic information about iBMC
        bmc_file : User-specified file to be download
        local_file_name : Local File Name
        logs: Indicates whether the downloaded file is a log file.
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
    file_path = "/tmp/web/%s" % bmc_file
    oem_info = ibmc.oem_info
    url = "%s/Actions/Oem/%s/Manager.GeneralDownload" % (ibmc.manager_uri, oem_info)
    token = ibmc.bmc_token
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {"TransferProtocol": "HTTPS", "Path": file_path}

    # send request to download files
    try:
        request_result = ibmc.request('POST', resource=url, headers=headers,
                                      data=payload, tmout=TIME_OUT)
        request_code = request_result.status_code
        if request_code == 200:
            ibmc.log_info("Start to save the file")
            with open(local_file_name, 'wb') as local_file:
                local_file.write(request_result.content)

            # Control file permissions, the file owner can read, write, and execute files.
            if file_type == "profile":
                os.chmod(local_file_name, stat.S_IRUSR | stat.S_IWUSR)
            else:
                os.chmod(local_file_name, stat.S_IRUSR | stat.S_IXUSR)
            log_msg = "Save file successfully!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_error = "Download files failed! The error code is: %s, " \
                      "The error info is: %s." \
                      % (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_error, False, ret)

    except Exception as e:
        error_msg = "Download files failed! The error info is: %s \n" % str(
            e)
        set_result(ibmc.log_error, error_msg, False, ret)

    return ret
