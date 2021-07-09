#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
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
module: ibmc_modify_raid

short_description: Modify volume

version_added: "2.5.0"

description:
    - "Modify properties of the specified volume"

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
  volumes:
    required: true
    default: None
    description:
      - Can set one or more volume information
  volumes/storage_id:
    required: true
    default: None
    description:
      - ID of the storage resource. It is a mandatory parameter. Format RAIDStorage+Controller_ID
  volumes/volume_id:
    required: true
    default: None
    description:
      - Volume resource ID. Format LogicalDrive+Volume_ID
  volumes/volume_name:
    required: false
    default: None
    description:
      - Volume name. It is an optional parameter. A string of up to 15 bytes.
        Value range ASCII code corresponding to 0x20 to 0x7E
  volumes/df_read_policy:
    required: false
    default: None
    choices: [NoReadAhead, ReadAhead]
    description:
      - Default read policy of the volume. It is an optional parameter
  volumes/df_write_policy:
    required: false
    default: None
    choices: [WriteThrough, WriteBackWithBBU, WriteBack]
    description:
      - Default write policy of the volume. It is an optional parameter
  volumes/df_cache_policy:
    required: false
    default: None
    choices: [CachedIO, DirectIO]
    description:
      - Default cache policy of the volume. It is an optional parameter
  volumes/boot_enable:
    required: false
    default: None
    choices: [True]
    description:
      - Whether it is the boot device
  volumes/bgi_enable:
    required: false
    default: None
    choices: [True, False]
    description:
      - Whether background initialization is enabled
  volumes/access_policy:
    required: false
    default: None
    choices: [ReadWrite, ReadOnly, Blocked]
    description:
      - Volume access policy. It is an optional parameter
  volumes/ssd_cache_enable:
    required: false
    default: None
    choices: [True, False]
    description:
      - Whether the CacheCade volume is used as the cache
  volumes/disk_cache_policy:
    required: false
    default: None
    choices: [Unchanged, Enabled, Disabled]
    description:
      - Cache policy for member disks. It is an optional parameter
"""

EXAMPLES = """
 - name: modify raid
    ibmc_modify_raid:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      volumes:
       - storage_id: "RAIDStorage0"
         volume_id: "LogicalDrive0"
         volume_name: "volume_name"
         df_read_policy: "NoReadAhead"
         df_write_policy: "WriteThrough"
         df_cache_policy: "CachedIO"
         boot_enable: True
         bgi_enable: False
         access_policy: "ReadWrite"
         ssd_cache_enable: False
         disk_cache_policy: "Unchanged"
"""

RETURNS = """
    {"result": True, "msg": "Modify RAID configuration successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_raid import modify_raid
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE


def ibmc_modify_raid_module(module):
    """
    Function:
        Modify RAID configuration
    Args:
        module       (class):
    Returns:
        {"result": False, "msg": 'not run modify raid yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/9 17:33
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = modify_raid(ibmc, module.params)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "volumes": {"required": True, "type": 'list'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_modify_raid_module, module, log, report)


if __name__ == '__main__':
    main()
