#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_ibmc_ip import get_ibmc_ip
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_get_ip

short_description: Get ibmc ip info

version_added: "2.5.0"

description:
    - "Query network port information of the manager resource"

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
"""

EXAMPLES = """
 - name: get ibmc ip
    ibmc_get_ip :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
"""

RETURNS = """
    {"result": True, "msg": "Get iBMC ethernet interface info successful!"}
"""


def ibmc_get_ip_module(module):
    """
    Function:
        Get iBMC ethernet interface information
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run get ibmc ip yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = get_ibmc_ip(ibmc)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_get_ip_module, module, log, report)


if __name__ == '__main__':
    main()
