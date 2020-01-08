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
module: ibmc_modify_account
short_description: modify ibmc accounts info 
version_added: "2.5.0"
description: modify ibmc accounts info 
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
  old_account_user:
    required: true
    default: 
    description: 
      -iBMC account  you want to modify 
  new_account_user:
    required: false
    default: 
    description: 
      - iBMC account  you want to modify to 
  new_account_pswd : 
    required: false
    default: 
    description: 
      - iBMC account password  you want to modify to        
  roleid :
    required: false
    default: 
    description: 
      - iBMC account role Id  you want to modify to ;
    choice:
      - Administrator
      - Operator
      - Commonuser
      - Noaccess
      - CustomRole1
      - CustomRole2
      - CustomRole3
      - CustomRole4 
  locked:
    required: false
    default: 
    description: 
      - set to False if you want to unLock the account
    choice:
      - "False"  
  enable:
    required: false
    default: 
    description: 
      - set to true if you want to enable the account 
    choice:
      - "False" 
      - "True"
  account_insecure_prompt_enabled :
    required: false
    default: 
    description: 
      - enable or disable the insecure prompt
    choice:
      - "False" 
      - "True"  
  login_interface: 
    required: false
    default: 
    description: 
      - "list of service the account can access,can be set to empty list [];  Available values in list:Web, SNMP, IPMI, SSH, SFTP, Local, Redfish"
  login_rule: 
    required: false
    default: 
    description: 
      - "list of login rules,can be set to empty list []; Available values in list:Rule1, Rule2, Rule3"
"""
EXAMPLES = r"""
 - name: modify account 
    ibmc_modify_account  :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}" 
      old_account_user: "test"
      new_account_user: "{{ account_user }}"
      new_account_pswd: "{{ account_pswd }}"
      roleid: "Administrator"
      locked: False
      enable: True
      account_insecure_prompt_enabled: True    
"""

RETURNS = """
    
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.ibmc_redfish_api.api_manage_account import modify_account,format_role_id
from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.utils import ansible_ibmc_run_module


def ibmc_modify_account_module(module):
    """
    Function:

    Args:
              ansible_module       (class):

    Returns:
        ret = {"result": False, "msg": 'not run modify account yet'}
    Raises:
        Exception
    Examples:

    Author: xwh
    Date: 2019/10/9 20:30
    """
    login_interface_dic = {
        "web": "Web",
        "snmp": "SNMP",
        "ipmi": "IPMI",
        "ssh": "SSH",
        "sftp": "SFTP",
        "local": "Local",
        "redfish": "Redfish"
    }

    login_rule_dic = {
        "rule1": "Rule1",
        "rule2": "Rule2",
        "rule3": "Rule3"
    }

    ret = {"result": False, "msg": 'not run modify account yet'}
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        config_dic = {}
        body_para = {}
        oem_dic = {
            "Huawei": {}
        }
        if module.params.get("new_account_user"):
            body_para["UserName"] = module.params.get("new_account_user")
        if module.params.get("new_account_pswd"):
            body_para["Password"] =  module.params.get("new_account_pswd")
        if module.params.get("roleid"):
            roleid = format_role_id( ibmc, module.params.get("roleid"))
            body_para["RoleId"] = roleid 
        if module.params.get("locked"):
            if module.params["locked"] is not False:
                raise Exception("the locked param can not be set to true")
            body_para["Locked"] = module.params["locked"]
        if module.params.get("enable"):
            body_para["Enabled"] = module.params["enable"]
        if module.params.get("account_insecure_prompt_enabled"):
            oem_dic["Huawei"]["AccountInsecurePromptEnabled"] = module.params["account_insecure_prompt_enabled"]
        login_interface = module.params.get("login_interface")
        
        if login_interface is not None:
            oem_dic["Huawei"]["LoginInterface"] = []
            if login_interface != []:
                for each_item in login_interface:
                    if  each_item is None:
                        raise Exception ("login_interface list member could not be None")
                    if each_item.lower() not in login_interface_dic.keys():
                          raise Exception ("the login_role param:%s is invalid: it should be in the list: %s" 
                                            % (each_item, str(login_interface_dic.values())))
                    oem_dic["Huawei"]["LoginInterface"].append(login_interface_dic.get(each_item.lower()))                      
        login_role = module.params.get("login_rule")
        
        if login_role is not None:
            oem_dic["Huawei"]["Loginrule"] = []
            if login_role != []:
                for each_item in login_role:
                    if  each_item is None:
                        raise Exception ("login_role list member could not be None")
                    if each_item.lower() not in login_rule_dic.keys():
                        raise Exception ("the login_role param:%s is invalid: it should be in the list: %s" 
                                            % (each_item, str(login_rule_dic.values())))
                    oem_dic["Huawei"]["Loginrule"].append(login_rule_dic.get(each_item.lower()))                          

        if oem_dic["Huawei"] != {}:
            body_para['Oem'] = oem_dic    
        config_dic[module.params["old_account_user"]] = body_para
        ret = modify_account(ibmc, config_dic)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "old_account_user": {"required": True, "type": 'str'},
            "new_account_user": {"required": False, "type": 'str'},
            "new_account_pswd": {"required": False, "type": 'str', "no_log": True},
            "roleid": {"required": False, "type": 'str'},
            "locked": {"required": False, "type": 'bool'},
            "enable": {"required": False, "type": 'bool'},
            "account_insecure_prompt_enabled": {"required": False, "type": 'bool'},
            "login_interface": {"required": False, "type": 'list'},
            "login_rule": {"required": False, "type": 'list'},

        },
        supports_check_mode=False)
    ansible_ibmc_run_module(ibmc_modify_account_module, module, log, report)


if __name__ == '__main__':
    main()
