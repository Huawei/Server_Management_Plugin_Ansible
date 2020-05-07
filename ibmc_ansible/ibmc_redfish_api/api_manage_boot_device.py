#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import requests

from ibmc_ansible.utils import set_result

BOOT_TARGET_DICT = {
    "cd": "Cd",
    "none": "None",
    "pxe": "Pxe",
    "floppy": "Floppy",
    "hdd": "Hdd",
    "biossetup": "BiosSetup"
}
BOOT_ENABLED_DICT = {
    "disabled": "Disabled",
    "once": "Once",
    "continuous": "Continuous"
}
BOOT_MODE_DICT = {
    "uefi": "UEFI",
    "legacy": "Legacy"
}


def set_boot_device(ibmc, boot_device_info):
    """

    Function:
        Set Boot device
    Args:
              ibmc                    (class):    Class that contains basic information about iBMC
              boot_device_info        (dict):     User-set boot device information
    Returns:
         {"result": True, "msg": "Set boot device info successful!"}
    Raises:
         Set boot device info failed!
    Examples:
         None
    Author:
    Date: 2019/10/23 21:44
    """
    ibmc.log_info("Start set boot device...")

    # Obtain user-configured IP information
    boot_target = boot_device_info.get('boot_target')
    boot_enabled = boot_device_info.get('boot_enabled')
    boot_mode = boot_device_info.get('boot_mode')

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Initialize payload
    boot_payload = {}

    # Current boot device, The optional parameters are: "Cd", "None", "Pxe", "Floppy", "Hdd", "BiosSetup"
    if boot_target:
        boot_target = BOOT_TARGET_DICT.get(str(boot_target).lower())
        if boot_target in BOOT_TARGET_DICT.values():
            boot_payload["BootSourceOverrideTarget"] = boot_target
        else:
            log_msg = 'The boot target is incorrect, ' \
                      'It should be "Cd", "None", "Pxe", "Floppy", "Hdd" or "BiosSetup"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Whether the boot settings are effective, The optional parameters are: "Disabled", "Once", "Continuous"
    if boot_enabled:
        boot_enabled = BOOT_ENABLED_DICT.get(str(boot_enabled).lower())
        if boot_enabled in BOOT_ENABLED_DICT.values():
            boot_payload["BootSourceOverrideEnabled"] = boot_enabled
        else:
            log_msg = 'The boot enabled is incorrect, It should be "Disabled", "Once" or "Continuous"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Boot mode, The optional parameters are: "UEFI", "Legacy"
    if boot_mode:
        boot_mode = BOOT_MODE_DICT.get(str(boot_mode).lower())
        if boot_mode in BOOT_MODE_DICT.values():
            boot_payload["BootSourceOverrideMode"] = boot_mode
        else:
            log_msg = 'The boot mode is incorrect, It should be "UEFI" or "Legacy"'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # If the input parameter is empty, prompt the user to enter the correct parameter in the yml file
    if boot_payload == {}:
        log_msg = 'The parameter is empty, please enter the correct parameter in the set_boot_device.yml file.'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    payload = {"Boot": boot_payload}

    # URL of the system resource
    url = ibmc.system_uri
    # Obtain token
    token = ibmc.bmc_token
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

    try:
        # Modify boot device by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers, data=payload, tmout=10)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Set boot device info successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Set boot device info failed! The error code is: %s . The error info is: %s" % \
                      (str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("Set boot device info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException(
            "Set boot device info failed! The error info is: %s" % str(e))

    return ret


def get_boot_device(ibmc):
    """

    Function:
        Get boot device
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
         {"result": True, "msg": "Get boot device info successful!"}
    Raises:
        None
    Examples:
         None
    Author:
    Date: 2019/10/23 21:08
    """
    ibmc.log_info("Start get boot device...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Get iBMC systems resource information
    request_result_json = ibmc.get_systems_resource()

    # Write the result to a file
    result = {
        "Boot": request_result_json.get("Boot")
    }

    # Update ret
    ret['result'] = True
    ret['msg'] = "Get boot device info successful! The boot device info is: %s" % str(result)

    ibmc.log_info("Get boot device info successful!")
    return ret
