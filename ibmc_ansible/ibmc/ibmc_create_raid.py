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
module: ibmc_create_raid

short_description: Create volume

version_added: "2.5.0"

description:
    - "Creating a volume"

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
  volumes/capacity_mbyte:
    required: false
    default: None
    description:
      - Volume capacity, must be an integer, the size unit is MB. It is an optional parameter
  volumes/stripe_size:
    required: false
    default: None
    choices: [65536, 131072, 262144, 524288, 1048576]
    description:
      - Stripe size of a volume, must be an integer. It is an optional parameter
  volumes/cachecade_flag:
    required: false
    default: None
    choices: [True, False]
    description:
      - Whether it is a CacheCade volume. It is an optional parameter
  volumes/drives:
    required: true
    default: None
    description:
      - Member disk list. It is a mandatory parameter. Format "disk1,disk2,.,diskN"
  volumes/volume_raid_level:
    required: true
    default: None
    choices: [RAID0, RAID1, RAID5, RAID6, RAID10, RAID50, RAID60]
    description:
      - RAID level of the volume. It is a mandatory parameter
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
  volumes/span_num:
    required: false
    default: None
    description:
      - Number of spans of the volume, must be an integer. It is an optional parameter
      - Set this parameter to 1 when creating a RAID0, RAID1, RAID5, or RAID6 array
      - Set this parameter to a value from 2 to 8 when creating a RAID10, RAID50, or RAID60 array
  volumes/access_policy:
    required: false
    default: None
    choices: [ReadWrite, ReadOnly, Blocked]
    description:
      - Volume access policy. It is an optional parameter
  volumes/disk_cache_policy:
    required: false
    default: None
    choices: [Unchanged, Enabled, Disabled]
    description:
      - Cache policy for member disks. It is an optional parameter
  volumes/init_mode:
    required: false
    default: None
    choices: [UnInit, QuickInit, FullInit]
    description:
      - Volume initialization mode. It is an optional parameter
"""

EXAMPLES = """
 - name: create raid
    ibmc_create_raid:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      volumes:
       - storage_id: "RAIDStorage0"
         capacity_mbyte: 1000
         stripe_size: 65536
         cachecade_flag: False
         drives: "0,1"
         volume_raid_level: "RAID0"
         volume_name: "new_raid"
         df_read_policy: "NoReadAhead"
         df_write_policy: "WriteThrough"
         df_cache_policy: "CachedIO"
         span_num: 1
         access_policy: "ReadWrite"
         disk_cache_policy: "Unchanged"
         init_mode: "UnInit"
"""

RETURNS = """
    {"result": True, "msg": "Create RAID configuration successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_raid import create_raid
from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE
from ibmc_ansible.utils import is_support_server


def ibmc_create_raid_module(module):
    """
    Function:
        Create RAID
    Args:
        module       (class):
    Returns:
        {"result": False, "msg": 'not run create raid yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """

    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = create_raid(ibmc, module.params)
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

    ansible_ibmc_run_module(ibmc_create_raid_module, module, log, report)


if __name__ == '__main__':
    main()
