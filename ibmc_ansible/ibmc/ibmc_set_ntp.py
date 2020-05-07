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
module: ibmc_set_ntp

short_description: Set ntp info

version_added: "2.5.0"

description:
    - "Modifying NTP resource properties"

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
  service_enabled:
    required: false
    default: None
    choices:
      - True
      - False
    description:
      - Enable or disable bmc ntp service
  pre_ntp_server:
    required: false
    default: None
    description:
      - Config preferred NtpServer, you can enter ipv4 ipv6 or domain name, NTP Server will be blanked when set to an empty string
  alt_ntp_server:
    required: false
    default: None
    description:
      - Config alternate NtpServer, you can enter ipv4 ipv6 or domain name, NTP Server will be blanked when set to an empty string
  server_auth_enabled:
    required: false
    default: None
    choices:
      - True
      - False
    description:
      - Enable or disable Server Authentication service
  ntp_address_origin:
    required: false
    default: None
    choices:
      - IPv4
      - IPv6
      - Static
    description:
      - Config Ntp Address Origin
  min_polling_interval:
    required: false
    default: 6
    description:
      - Config Min Polling Interval time, must be an integer, in 3~17 and <= max_polling_interval
  max_polling_interval:
    required: false
    default: 10
    description:
      - Config Max Polling Interval time, must be an integer, in 3~17 and >= min_polling_interval
"""

EXAMPLES = """
 - name: set ntp
    ibmc_set_ntp:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      service_enabled: True
      pre_ntp_server: "192.168.2.10"
      alt_ntp_server: "192.168.2.20"
      server_auth_enabled: False
      ntp_address_origin: "Static"
      min_polling_interval: 3
      max_polling_interval: 17
"""

RETURNS = """
    {"result": True, "msg": "Set NTP configuration resource info successful!"}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_ntp import set_ntp
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_set_ntp_module(module):
    """
    Function:
        Set NTP configuration resource
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run set ntp yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """
    ret = {"result": False, "msg": 'not run set ntp yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = set_ntp(ibmc, module.params)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "service_enabled": {"required": False, "type": 'bool'},
            "pre_ntp_server": {"required": False, "type": 'str'},
            "alt_ntp_server": {"required": False, "type": 'str'},
            "server_auth_enabled": {"required": False, "type": 'bool'},
            "ntp_address_origin": {"required": False, "type": 'str'},
            "min_polling_interval": {"required": False, "type": 'int'},
            "max_polling_interval": {"required": False, "type": 'int'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_ntp_module, module, log, report)


if __name__ == '__main__':
    main()
