#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
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
module: ibmc_collect_sel_logs
short_description: Collect iBMC SEL logs
version_added: "2.5.0"
description:
    - "Collecting SEL log"
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
  save_mode:
    required: true
    default: local
    description:
      - place to save logs
  file_server_ip:
    required: false
    default: None
    description:
      - ip address of file server
  file_server_user:
    required: false
    default: None
    description:
      - the user of file server
  file_server_user:
    required: false
    default: None
    description:
      - the password of file server
  file_name:
    required: True
    default: None
    description:
      - Log file storage path and file name
"""

EXAMPLES = """
 - name: collect sel logs
    ibmc_collect_sel_logs :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      save_mode: "sftp"
      file_server_ip: "sftp_server_ip"
      file_server_user: "{{ sftp_user }}"
      file_server_pswd: "{{ sftp_pswd }}"
      file_name: "/usr/SEL_LOG.tar.gz"
"""

RETURNS = """
    {"result": True, "msg": "Collect logs successfully!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_logs import collect_log
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server


def ibmc_collect_log_module(module):
    """
    Function:
        Collect iBMC logs
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2021/2/22
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            save_location = {"save_mode": module.params.get("save_mode"),
                             "file_server_ip": module.params.get("file_server_ip"),
                             "file_server_user": module.params.get("file_server_user"),
                             "file_server_pswd": module.params.get("file_server_pswd")
                             }
            ret = collect_log(ibmc, save_location, module.params.get("file_name"), log_type="SEL")
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "save_mode": {"required": True, "type": 'str'},
            "file_server_ip": {"required": False, "type": 'str'},
            "file_server_user": {"required": False, "type": 'str'},
            "file_server_pswd": {"required": False, "type": 'str', "no_log": True},
            "file_name": {"required": True, "type": 'str'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_collect_log_module, module, log, report)


if __name__ == '__main__':
    main()
