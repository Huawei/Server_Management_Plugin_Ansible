#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
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
module: ibmc_deploy_os_by_service_cd
short_description:  deploy os by service cd 
version_added: "2.5.0"
description: deploy os by service cd
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
  service_cd_img:
    required: true
    default:
    description:
      - service cd image file path
  os_img:
    required : true
    default:
    description:
      - os image file path
  os_type:
    required : true 
    default:
    description:
      - os type
    choice:
      - CentOS6U7_x64
      - CentOS6U8_x64
      - CentOS6U9_x64
      - CentOS7U0_x64
      - CentOS7U1_x64
      - CentOS7U2_x64
      - CentOS7U3_x64
      - CentOS7U4_x64
      - CentOS7U5_x64
      - RHEL6U7_x64
      - RHEL6U8_x64
      - RHEL6U9_x64
      - RHEL7U0_x64
      - RHEL7U1_x64
      - RHEL7U2_x64
      - RHEL7U3_x64
      - RHEL7U4_x64
      - RHEL7U5_x64
      - SLES11SP3_x64
      - SLES11SP4_x64
      - SLES12_x64
      - SLES12SP1_x64
      - SLES12SP2_x64
      - SLES12SP3_x64
      - ESXi5.5_x64
      - ESXi6.0_x64
      - ESXi6.5_x64
      - ESXi6.7_x64  
      - Win2008_R2_x64
      - Win2012_x64
      - Win2012_R2_x64
      - Win2016_x64
      - Ubuntu16.04_x64
      - Ubuntu14.04_x64
  cd_key:
    required : false 
    default:
    description:
      - os type  
  password:
    required : false 
    default:
    description:
      - password 
  hostname:
    required : false 
    default:
    description:
      - Host Name 
  owner_name:
    required : false 
    default:
    description:
      - Owner Name            
  language:
    required : false 
    default:
    description:
      - language   
  org_name:
    required : false 
    default:
    description:
      - Organize Name
  position:
    required : false 
    default:
    description:
      - Position where the os install           
  partitions:
    required : false 
    default:
    description:
      - list of partition info 
  timezone:
    required : false 
    default:
    description:
      - timezone     
  mode:
    required : false 
    default:
    description:
      - mode to install;1 for standard, 2 for full , 3 for Customized 
    choice:
      - "1"
      - "2"
      - "3"    
  rpms:
    required : false 
    default:
    description:
      - list of rpm packages you want to install 
  script:
    required : false 
    default:
    description:
      - install script 
  software:
    required : false 
    default:
    description:
      - software you want to install   
    choice:
      - "ibma" 
  win_os_name:
    required : false 
    default:
    description: windows os name , only for windows os 
    choice:
      - Windows Server 2016 ServerStandard
      - Windows Server 2016 ServerStandardCore
      - Windows Server 2016 ServerDataCenter
      - Windows Server 2016 ServerDataCenterCore
      - Windows Server 2012 R2 ServerStandard
      - Windows Server 2012 R2 ServerStandardCore
      - Windows Server 2012 R2 ServerDataCenter
      - Windows Server 2012 R2 ServerDataCenterCore  
      - Windows Server 2012 ServerStandard
      - Windows Server 2012 ServerStandardCore
      - Windows Server 2012 ServerDataCenter
      - Windows Server 2012 ServerDataCenterCore  
      - Windows Server 2008 R2 ServerStandard
      - Windows Server 2008 R2 ServerStandardCore
      - Windows Server 2008 R2 ServerEnterprise,
      - Windows Server 2008 R2 ServerEnterpriseCore
      - Windows Server 2008 R2 ServerDataCenter
      - Windows Server 2008 R2 ServerDataCenterCore
      - Windows Server 2008 R2 ServerWeb
      - Windows Server 2008 R2 ServerWebCore
      
"""
EXAMPLES = r"""
tasks:
  - name: deploy os by service cd
    ibmc_deploy_os_by_service_cd:
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      service_cd_img: "nfs://172.26.200.11/data/serviceCD.iso"
      os_img: "nfs://172.26.200.11/data/CentOS-7.3-x86_64-DVD-1611.iso"
      os_type: "CentOS7U3_x64"
      cd_key: 
      password: "{{ os_pswd }}"
      hostname: 
      owner_name:
      language:
      org_name:
      position: "disk"
      partitions:
        - partition: "swap:swap:10000|/:ext3:1"
      timezone: "America/New_York" 
      mode: 
      rpms: 
        - rpm:
      script:
      software: "ibma"   
"""
from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_deploy_os_by_service_cd import deploy_os_process
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_deploy_os_by_service_cd_process(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run deploy os by ServiceCD yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    ret = {"result": False, "msg": 'not run deploy os by ServiceCD yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = deploy_os_process(ibmc, module.params)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "service_cd_img": {"required": True, "type": 'str', "no_log": True},
            "os_img": {"required": True, "type": 'str', "no_log": True},
            "os_type": {"required": True, "type": 'str'},
            "cd_key": {"required": False, "type": 'str', "no_log": True},
            "password": {"required": False, "type": 'str', "no_log": True},
            "hostname": {"required": False, "type": 'str'},
            "owner_name": {"required": False, "type": 'str'},
            "language": {"required": False, "type": 'str'},
            "org_name": {"required": False, "type": 'str'},
            "position": {"required": False, "type": 'str'},
            "partitions": {"required": False, "type": 'list'},
            "timezone": {"required": False, "type": 'str'},
            "mode": {"required": False, "type": 'str'},
            "rpms": {"required": False, "type": 'list'},
            "script": {"required": False, "type": 'str'},
            "software": {"required": False, "type": 'str'},
            "win_os_name":{"required": False, "type": 'str'},
        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_deploy_os_by_service_cd_process, module, log, report)


if __name__ == '__main__':
    main()
