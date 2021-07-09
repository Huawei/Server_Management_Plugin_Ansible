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
import json

from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH

# Command delivery timed out.
TIME_OUT = 30
# Request method set
REQUEST_METHOD = ("POST", "GET", "PATCH", "DELETE")
# Status code for successes request
STATUS_CODE = (200, 201, 202)


def common_api(ibmc, url, request_method, request_body):
    """
    Function:
        Common api
    Args:
        ibmc : information from yml
        url : user-set request resource
        request_method : user-set request method
        request_body : user-set request body content
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    request_method = request_method.upper()
    # The default request body is empty
    if not request_body:
        request_body = '{}'

    check_res = check_user_set(ibmc, url, request_method, request_body)
    if not check_res.get('result'):
        return check_res

    # Obtains the payload
    try:
        payload = json.loads(request_body)
    except ValueError:
        error = "The format of request_body is incorrect"
        set_result(ibmc.log_error, error, False, ret)
        return ret

    try:
        url = "https://%s" % ibmc.ip + url
        request_res = send_request(ibmc, url, request_method, payload)
    except Exception as e:
        set_result(ibmc.log_error, str(e), False, ret)
        return ret

    # Parsing the request result
    if not request_res.get('result'):
        return request_res

    if request_method != "GET":
        log_info = "%s request successfully! The info is: %s \n" % (request_method, request_res.get('msg'))
        set_result(ibmc.log_info, log_info, True, ret)
        return ret

    # Save the result of "GET" request as a file.
    filename = os.path.join(
        IBMC_REPORT_PATH, "common_api/%s_temp_common_api.json" % str(ibmc.ip))
    write_result(ibmc, filename, request_res.get('msg'))
    log_info = "GET request successfully! The result saved in " \
               "/common_api/%s_temp_common_api.json." % str(ibmc.ip)
    set_result(ibmc.log_info, log_info, True, ret)

    return ret


def send_request(ibmc, url, request_method, payload):
    """
    Function:
        Send the request
    Args:
        ibmc : information from yml
        url : user-set request resource
        request_method : user-set request method
        request_body : request body content
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    if request_method == "PATCH":
        e_tag = ibmc.get_etag(url)
        headers['If-Match'] = e_tag
    request_code = None

    # Send request
    try:
        request_result = ibmc.request(request_method, resource=url,
                                      headers=headers,
                                      data=payload, tmout=TIME_OUT)
        # Analyze the request result.
        request_code = request_result.status_code
        request_json = request_result.json()
        # Parsing the request result
        if request_code not in STATUS_CODE:
            log_error = "%s request failed! The error code is: %s. The error info is: %s \n" % \
                        (request_method, request_code, str(request_json))
            set_result(ibmc.log_error, log_error, False, ret)
            return ret
        else:
            ret["msg"] = str(request_json)
            return ret

    except Exception as e:
        log_error = "%s request failed! The error code is: %s. The error info is: " \
                    "%s  \n" % (request_method, request_code, e)
        raise requests.exceptions.RequestException(log_error)


def check_user_set(ibmc, url, request_method, request_body):
    """
    Function:
        Validity of parameters set by users
    Args:
        ibmc : information from yml
        url : user-set request resource
        request_method : user-set request method
        request_body : user-set request body content
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Verifying Parameters Configured by Users
    if request_method not in REQUEST_METHOD:
        log_error = "The request method is incorrect. " \
                    "Please set it in the common_api.yml file"
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    if request_method in ("GET", "DELETE") and request_body != '{}':
        log_error = "When request_method is 'Get' or 'Delete', request_body must be empty."
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    if not isinstance(request_body, str) or not request_body.startswith("{"):
        log_error = "Incorrect request_body format. Please set it in the common_api.yml file."
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    if not url.startswith("/"):
        log_error = "The url is incorrect. Please set it in the common_api.yml file."
        set_result(ibmc.log_error, log_error, False, ret)
        return ret

    msg = "Check parameter setting successfully!"
    set_result(ibmc.log_info, msg, True, ret)
    return ret
