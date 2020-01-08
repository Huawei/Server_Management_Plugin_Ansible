#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: ibmc_create_account
short_description: create a new ibmc account
version_added: "2.5.0"
description: create a new ibmc account
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
        default: 
        description:
            - iBMC user password used for authentication 
    new_account_user:
        required: true
        default: 
        description:
            - iBMC Account
    new_account_pswd:
        required: true
        default: 
        description:
            - password  or iBMC Account
    roleid:
        required: true
        default: 
        description:
           - "role for iBMC Account"
        choice:
           - Administrator 
           - Operator 
           - Commonuser  
           - Noaccess
           - CustomRole1 
           - CustomRole2
           - CustomRole3
           - CustomRole4
"""
EXAMPLES = r"""
    - name: create account 
          ibmc_create_account:
            ibmc_ip: "{{ ibmc_ip }}"
            ibmc_user: "{{ ibmc_user }}"
            ibmc_pswd: "{{ ibmc_pswd }}" 
            new_account_user: "{{ account_user }}"
            new_account_pswd: "{{ account_pswd }}"
            roleid: "Administrator"

"""

RETURNS = """
    
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_manage_account import create_account
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_create_account_module(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run create account yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    ret = {"result": False, "msg": 'not run create account yet'}

    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = create_account(ibmc, module.params["new_account_user"], module.params["new_account_pswd"],
                             module.params["roleid"])
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "new_account_user": {"required": True, "type": 'str'},
            "new_account_pswd": {"required": True, "type": 'str', "no_log": True},
            "roleid": {"required": True, "type": 'str'},
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_create_account_module, module, log, report)


if __name__ == '__main__':
    main()
