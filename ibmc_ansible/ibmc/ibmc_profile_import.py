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
module: ibmc_profile_import
short_description: import the server profile
version_added: "2.5.0"
description: import the server profile
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
  file_name:
    required: true
    default:
    description:
       - the file name you want to import
  local_import:
    required: true
    default:
    description:
      - local file path of the Ansible environment where the profile file is saved
  remote_import:
    required: true
    default:
    description:
      - file_path on BMC or file_server where the profile is saved
  file_server_user:
    required: false
    default:
    description:
      - remote file server user name
  file_server_pswd:
    required: false
    default:
    description:
      - remote file server password
"""

EXAMPLES = r"""
 - name: import profile
    ibmc_profile_import:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      file_name: "172.26.0.1_20210318045050_profile.xml"
      local_import: "/home/plugin"
"""

RETURNS = """

"""

import os
from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import set_result
from ibmc_ansible.ibmc_redfish_api.api_server_profile import server_profile
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import is_support_server
from ibmc_ansible.utils import SERVERTYPE
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import remote_file_path


def ibmc_profile_import_module(module):
    """
    Function:
        import BIOS, BMC, and RAID Controller Configurations
    Args:
        module  : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/10/9 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            all_file_path = (module.params.get("local_import"), module.params.get("remote_import"))
            if all(all_file_path) or not any(all_file_path):
                log_error = "Profile import failed! Please select a profile " \
                            "import mode from local_import or remote_import."
                set_result(ibmc.log_error, log_error, False, ret)
                return ret

            try:
                local, profile = get_profile_name(ibmc, module)
            except Exception as e:
                log_error = "Profile import failed! %s" % str(e)
                set_result(ibmc.log_error, log_error, False, ret)
                return ret
            command = "import"
            ret = server_profile(ibmc, profile, command, local)
    return ret


def get_profile_name(ibmc, module):
    """
    Function:
        get profile name
    Args:
        module : information from yml
    Returns:
        local: False
        profile: profile name
    Raises:
        None
    Date: 2019/10/9 20:30
    """
    file_name = module.params.get("file_name")

    file_path = module.params.get("local_import") or module.params.get("remote_import")
    local = False

    if file_path == module.params.get("local_import"):
        local = True
        profile = os.path.join(file_path, file_name)
    elif file_path.startswith("/tmp"):
        profile = os.path.join(file_path, file_name)
    else:
        file_path = remote_file_path(file_path, module)
        profile = os.path.join(file_path, file_name)

    return local, profile


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "file_name": {"required": True, "type": 'str'},
            "local_import": {"required": False, "type": 'str'},
            "remote_import": {"required": False, "type": 'str'},
            "file_server_user": {"required": False, "type": 'str', "no_log": True},
            "file_server_pswd": {"required": False, "type": 'str', "no_log": True}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_profile_import_module, module, log, report)


if __name__ == '__main__':
    main()
