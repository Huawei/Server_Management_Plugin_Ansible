#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os
from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_server_profile import server_profile
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: ibmc_server_profile
short_description: export or import the server profile
version_added: "2.5.0"
description: export or import the server profile 
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
  command:
    required: true
    default: 
    description:
      - import or export
    choice:
      - import
      - export        
  file_path:
    required: true
    default: 
    description:
      - file path in ibmc in where the profile is saved
  file_name:
    reuired: false
    default:
    description:
       - the file name you want to import or export ;if the file name is empty ,ibmc_ansible_profile will used the default name; such as 172.26.201.2_profile.xml              
"""
EXAMPLES = r"""
 - name:  server profile 
    ibmc_server_profile :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      command: "import"
      file_path: "/tmp"
      file_name: "profile.xml"
"""

RETURNS = """

"""


def ibmc_server_profile_module(ansible_module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run server profile yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    with IbmcBaseConnect(ansible_module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            if ansible_module.params.get("file_name") is None or ansible_module.params.get("file_name") == "":
                profile = os.path.join(ansible_module.params.get("file_path"),
                                       "%s_profile.xml" % ansible_module.params.get("ibmc_ip"))
            else:
                profile = os.path.join(ansible_module.params.get("file_path"), ansible_module.params.get("file_name"))
            ret = server_profile(ibmc, profile, ansible_module.params["command"])
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "command": {"required": True, "type": 'str'},
            "file_path": {"required": True, "type": 'str', "no_log": True},
            "file_name": {"required": False, "type": 'str'},
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_server_profile_module, module, log, report)


if __name__ == '__main__':
    main()
