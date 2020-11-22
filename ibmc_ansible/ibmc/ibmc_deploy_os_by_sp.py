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
from ibmc_ansible.ibmc_redfish_api.api_deploy_os_by_sp import deploy_os_by_sp_process
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: ibmc_deploy_os_by_sp
short_description:  deploy os by sp 
version_added: "2.5.0"
description: deploy os by sp
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
  os_img:
    required: true
    default: 
    description: 
      - os img file you want to deploy 
  os_config:
    required: true
    default: 
    description: 
      - "os config json the json keys as follows:
                {
            InstallMode: InstallMode_value,
            OSType: OSType_value,
            BootType: BootType_value,
            CDKey: CDKey_value,
            RootPwd: RootPwd_value,
            HostName: HostName_value,
            Autopart: Autopart_value,
            MediaType:MediaType_value,
            MedodaType:MediaType_value,
            AutoPosition: AutoPosition_value,
            Language: Language_value
            TimeZone: TimeZone_value
            Keyboard: Keyboard_value,
            CheckFirmware: CheckFirmware_value,
            Partition: [Partition_value],
            Software: [Software_value],
            NetCfg: [
            {
            Device: device_value,
            IPv4Addresses: [ipv4addr_value],
            IPv6Addresses: [ipv6addr_value],
            NameServers: [servers_value] ,
            },
            ],
            Packages: [
            {
            PackageName: [packagename_value],
            PatternName: [patternname_value]
            }
            ]
        }"
       
"""
EXAMPLES = r"""
  - name:  ibmc deploy centos7u3 by sp
    ibmc_deploy_os_by_sp:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      os_img: "nfs://172.26.200.11/data/centeros7u3.iso"
      os_config:
        InstallMode: "Recommended"
        OSType: "CentOS7U3"
        CDKey: ""
        RootPwd: "{{ os_pswd }}"
        HostName: "{{ os_user }}"
        Language: "en_US.UTF-8"
        TimeZone: "America/New_York"
        Keyboard: "us"
        CheckFirmware: False
        Partition: []
        Autopart: True
        AutoPosition: True
        Software: []
        NetCfg:
          - Device:
              Name: "eth10086"
              MAC: "04:B0:E7:48:27:84"
          - IPv4Addresses:
              - Address: "192.168.2.44"
                SubnetMask: "255.255.0.0"
                Gateway: "192.168.2.1"
                AddressOrigin: "Static"
          - IPv6Addresses:
              - Address: ""
                PrefixLength: ""
                Gateway: ""
                AddressOrigin: "Static"
          - NameServers:
               - DNS: "192.168.2.1"
               - DNS: "192.168.2.2"
"""

RETURNS = """

"""


def ibmc_deploy_os_by_sp_process(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run deploy os by SP yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = deploy_os_by_sp_process(ibmc, module.params["os_img"],
                                          module.params["os_config"])
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "os_img": {"required": True, "type": 'str', "no_log": True},
            "os_config": {"required": True, "type": 'dict', "no_log": True},
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_deploy_os_by_sp_process, module, log, report)


if __name__ == '__main__':
    main()
