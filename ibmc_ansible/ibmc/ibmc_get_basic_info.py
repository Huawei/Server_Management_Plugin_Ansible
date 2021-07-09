#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ibmc_get_account
short_description: Get server information
version_added: "2.5.0"
description:
    - Obtain the iBMC, BIOS, CPLD version and SP, CPU, memory, drive information
options:
    ibmc_ip:
        required: true
        default: None
        description:
            - iBMC IP address
    ibmc_user:
        required: true
        default: None
        description:
            - iBMC user name used for authentication
    ibmc_pswd:
        required: true
        default: None
        description:
            - iBMC user password used for authentication
    csv_format:
        required: false
        default: False
        choices: [ True, False ]
        description:
            - Whether to write the result to a CSV file
'''

EXAMPLES = r'''
- name: get ibmc basic info
  ibmc_get_basic_info:
    ibmc_ip: "{{ ibmc_ip }}"
    ibmc_user: "{{ ibmc_user }}"
    ibmc_pswd: "{{ ibmc_pswd }}"
    csv_format: True
'''

RETURNS = r'''
    "msg": "Get basic info successful!"
'''

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_redfish_api.api_basic_info import get_basic_info
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_get_basic_info(module):
    """
    Function:
        Get Server basic info
    Args:
        module       (class):
    Returns:
        {"result": False, "msg": ''}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/23 15:11
    """
    ret = {"result": False, "msg": 'not run get basic info yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = get_basic_info(ibmc, module.params.get("csv_format"))
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "csv_format": {"required": False, "type": 'bool'}
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_get_basic_info, module, log, report)


if __name__ == '__main__':
    main()
