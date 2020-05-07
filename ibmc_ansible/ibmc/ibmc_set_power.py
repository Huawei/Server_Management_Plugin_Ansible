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
module: ibmc_set_power
short_description: manager server power
version_added: "2.5.0"
description: manager server power
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
  power_cmd:
    required: true
    default: 
    description:
      - power off or power on the server; 
    choice:
      - poweron 
      - poweroff
      - forcerestart
      - gracefulshutdown
      - forcepowercycle
      - nmi 
"""
EXAMPLES = r"""
 - name:  mananger ibmc power
    ibmc_set_power:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      power_cmd: 'poweron' 
"""

RETURNS = """
     
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_power_manager import manage_power
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_power_mannager_module(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run set power yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    ret = {"result": False, "msg": 'not run set power yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = manage_power(ibmc, module.params["power_cmd"])
    return ret

def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "power_cmd": {"required": True, "type": 'str'}
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_power_mannager_module, module, log, report)

if __name__ == '__main__':
    main()
