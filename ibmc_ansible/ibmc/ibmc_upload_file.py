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
module: ibmc_upload_file
short_description: upload file
version_added: "2.5.0"
description:
    - "upload file to /tmp/web/ of ibmc"
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
  imgfile:
    required: true
    default: None
    description:
      - User-specified file to be uploaded
"""

EXAMPLES = """
 - name: file upload
    ibmc_upload_file :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      imgfile: "/home/plugin/SOO.keytab"
"""

RETURNS = """
    {"result": True, "msg": "Upload files successfully!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_file import upload_file
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server


def ibmc_upload_file_module(module):
    """
    Function:
        Upload files
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
            ret = upload_file(ibmc, module.params["imgfile"])
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "imgfile": {"required": True, "type": 'str'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_upload_file_module, module, log, report)


if __name__ == '__main__':
    main()
