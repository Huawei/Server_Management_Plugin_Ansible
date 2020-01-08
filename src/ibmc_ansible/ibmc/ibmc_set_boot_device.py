#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_set_boot_device

short_description: Set boot device

version_added: "2.5.0"

description:
    - "Modifying boot device information"

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
  boot_target:
    required: false
    default: None
    choices:
      - Cd
      - None
      - Pxe
      - Floppy
      - Hdd
      - BiosSetup
    description:
      - Current boot device
  boot_enabled:
    required: false
    default: None
    choices:
      - Disabled
      - Once
      - Continuous
    description:
      - Whether the boot settings are effective
  boot_mode:
    required: false
    default: None
    choices:
      - UEFI
      - Legacy
    description:
      - Boot mode
"""

EXAMPLES = """
 - name: set boot device
    ibmc_set_boot_device:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      boot_target: "Cd"
      boot_enabled: "Once"
      boot_mode: "Legacy"
"""

RETURNS = """
    {"result": True, "msg": "Set boot device info successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_boot_device import set_boot_device
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_set_boot_device_module(module):
    """
    Function:
        Set boot device
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run set boot device yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """
    ret = {"result": False, "msg": 'not run set boot device yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = set_boot_device(ibmc, module.params)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "boot_target": {"required": False, "type": 'str'},
            "boot_enabled": {"required": False, "type": 'str'},
            "boot_mode": {"required": False, "type": 'str'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_boot_device_module, module, log, report)


if __name__ == '__main__':
    main()
