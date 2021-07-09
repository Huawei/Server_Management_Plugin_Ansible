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

DOCUMENTATION = """
module: ibmc_inband_fw_update
short_description: update inband firmware
version_added: "2.5.0"
description: update inband firmware
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
  image_url:
    required: true
    default:
    description:
      - firmware path list which need to be update
  file_server_user:
    required: false
    default:
    description:
      - file server user which used to download firmware
  file_server_pswd:
    required: false
    default:
    description:
      - file server password which used to download firmware
"""

EXAMPLES = r"""
 - name: inband firmware update
    ibmc_inband_fw_update :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      image_url:
        - "sftp://172.26.200.11/data/NIC-LOM-X722-10GE_SFP-GE_Electrical-FW-3.33_0x80000f09.zip"
      file_server_user: "{{scpuser}}"
      file_server_pswd: "{{scppswd}}"
"""

RETURNS = """

"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.ibmc_redfish_api.api_inband_fw_update import sp_upgrade_fw_process
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import SERVERTYPE


def ibmc_inband_fw_update_module(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        "result": False
        "msg": 'not run update inband firmware yet'
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            file_path_list = []
            for each_item in module.params["image_url"]:
                if 'nfs' in each_item.lower() or ("file_server_user" not in module.params) or (
                            module.params["file_server_user"] is ''):
                    file_path_list.append(each_item)
                else:
                    file_url = each_item.replace("://", "://%s:%s@" % (
                        module.params["file_server_user"], module.params["file_server_pswd"]))
                    file_path_list.append(file_url)
            ret = sp_upgrade_fw_process(ibmc, file_path_list)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "image_url": {"required": True, "type": 'list'},
            "file_server_user": {"required": False, "type": 'str'},
            "file_server_pswd": {"required": False, "type": 'str', "no_log": True},

        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_inband_fw_update_module, module, log, report)


if __name__ == '__main__':
    main()
