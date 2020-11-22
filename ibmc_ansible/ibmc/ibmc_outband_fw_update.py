#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_outband_fw_update import update_fw
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: ibmc_outband_fw_update
short_description: update outband firmware 
version_added: "2.5.0"
description: update outband firmware 
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
      - firmware path  
  protocol:  
    required: false
    default: 
    description: 
      - protocol which used to download  firmware  
    choice:
      - HTTPS
      - SCP
      - SFTP
      - CIFS
      - TFTP
      - NFS           
"""
EXAMPLES = r"""
 - name: outband fw update
    ibmc_outband_fw_update:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}" 
      image_url:"nfs://172.16.2.2/tmp/package/cpldimage.hpm"
      protocol:'NFS'
"""

RETURNS = """
   
"""


def ibmc_outband_fw_update_module(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run update outband firmware yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    ret = {"result": False, "msg": 'not run update outband firmware yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        if (module.params.has_key("protocol")):
            ret = update_fw(ibmc, module.params["image_url"], module.params["protocol"])
        else:
            ret = update_fw(ibmc, module.params["image_url"])
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "image_url": {"required": True, "type": 'str', "no_log": True},
            "protocol": {"required": False, "type": 'str'}
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_outband_fw_update_module, module, log, report)


if __name__ == '__main__':
    main()
