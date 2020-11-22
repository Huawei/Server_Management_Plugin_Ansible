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

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_snmp import set_snmp_trap
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_set_snmp_trap

short_description: Set snmp trap info

version_added: "2.5.0"

description:
    - "Modifying SNMP trap resource properties"

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
      - Whether trap is enabled
  trap_version:
    required: false
    default: None
    choices:
      - V1
      - V2C
      - V3
    description:
      - Trap version
  trap_v3_user:
    required: false
    default: None
    description:
      - SNMPv3 user name, valid only for trap version is V3
  trap_mode:
    required: false
    default: None
    choices:
      - OID
      - EventCode
      - PreciseAlarm
    description:
      - Trap mode
  trap_server_identity:
    required: false
    default: None
    choices:
      - BoardSN
      - ProductAssetTag
      - HostName
    description:
      - Host identifier
  alarm_severity:
    required: false
    default: None
    choices:
      - Critical
      - Major
      - Minor
      - Normal
    description:
      - Severity levels of the alarm to be sent
  trap_servers:
    required: false
    default: None
    description:
      - Can set one or more trap server, When all parameters of the trap server are empty, it indicates that the trap server is not configured
  trap_servers/trap_enabled:
    required: false
    default: None
    choices:
      - True
      - False
    description:
      - Whether the trap server is enabled
  trap_servers/trap_server_address:
    required: false
    default: None
    description:
      - Server address, you can enter ipv4 ipv6 or domain name
  trap_servers/trap_server_port:
    required: false
    default: None
    description:
      - "Server port number, must be an integer, Available value range: 1 to 65535"
"""

EXAMPLES = """
 - name: set snmp trap
    ibmc_set_snmp_trap:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      service_enabled: True
      trap_version: "V3"
      trap_v3_user: "root"
      trap_mode: "OID"
      trap_server_identity: "HostName"
      alarm_severity: "Normal"
      trap_servers:
        - trap_enabled: True
          trap_server_address: "192.168.2.10"
          trap_server_port: 160
        - trap_enabled: True
          trap_server_address: "192.168.2.11"
          trap_server_port: 161
        - trap_enabled: False
          trap_server_address: "192.168.2.12"
          trap_server_port: 162
        - trap_enabled: False
          trap_server_address: "192.168.2.13"
          trap_server_port: 163
"""

RETURNS = """
    {"result": True, "msg": "Set SNMP trap resource properties successful!"}
"""


def ibmc_set_snmp_trap_module(module):
    """
    Function:
        Set SNMP trap resource properties
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run set snmp trap yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/11/4 17:33
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = set_snmp_trap(ibmc, module.params)
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "community": {"required": False, "type": 'str', "no_log": True},
            "service_enabled": {"required": False, "type": 'bool'},
            "trap_version": {"required": False, "type": 'str'},
            "trap_v3_user": {"required": False, "type": 'str'},
            "trap_mode": {"required": False, "type": 'str'},
            "trap_server_identity": {"required": False, "type": 'str'},
            "alarm_severity": {"required": False, "type": 'str'},
            "trap_servers": {"required": False, "type": 'list'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_snmp_trap_module, module, log, report)


if __name__ == '__main__':
    main()
