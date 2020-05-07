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
module: ibmc_delete_raid

short_description: Delete volume

version_added: "2.5.0"

description:
    - "Delete the specified volume"

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
  storage_id:
    required: true
    default: None
    description:
      - ID of the storage resource
      - "Delete one RAID storage, Format: RAIDStorage+Controller_ID"
      - "Delete multiple RAID storage, Format: RAIDStorage+Controller_ID1,RAIDStorage+Controller_ID2,..."
      - "Delete all RAID storage, Format: all"
  volume_id:
    required: true
    default: None
    description:
      - Volume resource ID
      - "Delete one volume, Format: LogicalDrive+Volume_ID"
      - "Delete multiple volume, Format: LogicalDrive+Volume_ID1,LogicalDrive+Volume_ID2,..."
      - "Delete all volume, Format: all"
"""

EXAMPLES = """
 - name: delete raid
    ibmc_delete_raid:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      storage_id: "RAIDStorage0,RAIDStorage1"
      volume_id: "LogicalDrive0,LogicalDrive1"
"""

RETURNS = """
    {"result": True, "msg": "Delete RAID configuration successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_raid import delete_raid
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_delete_raid_module(module):
    """
    Function:
        Delete RAID configuration
    Args:
        module       (class):
    Returns:
        {"result": False, "msg": 'not run delete raid yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/12 15:11
    """
    ret = {"result": False, "msg": 'not run delete raid yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = delete_raid(ibmc, module.params)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "storage_id": {"required": True, "type": 'str'},
            "volume_id": {"required": True, "type": 'str'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_delete_raid_module, module, log, report)


if __name__ == '__main__':
    main()
