#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Huawei.
#
# This file is part of Ansible
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '0.1'}

DOCUMENTATION = """
module: ibmc
version_added: "1.2"
short_description: Manage Huawei Server through iBMC Redfish APIs
options:
  category:
    required: true
    default: None
    description:
      - Action category to execute on server
  command:
    required: true
    default: None
    description:
      - Command to execute on server
  ibmcip:
    required: true
    default: None
    description:
      - iBMC IP address
  ibmcuser:
    required: false
    default: root
    description:
      - iBMC user name used for authentication
  ibmcpswd:
    required: false
    default: 
    description:
      - iBMC user passwore used for authentication
"""

import os
import requests
import json
import re
import sys
import time
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from ansible.module_utils.basic import *

sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from cfgBmc import *
from deployOs import *
from getBasicInfo import *
from powerManage import *
from updateFW import *
from cfgRaid import *
from cfgTrap import *
from serverProfile import *
from getRaidInfo import *
from cfgNTP import *
from deployOsBySp import *
from upgradeFwBySp import *
from upgradeFwBySp import spUpgradeFwProcess as upgradeFwBySp 


session_uri  = "/Sessions"
tasksvc_uri  = "/TaskService"
isHTTPS = True

'''
#==========================================================================
# @Method: main
# @command: main
# @Param: 
# @date: 2017.9.15
#==========================================================================
'''
def main():
    result = {}
    module = AnsibleModule(
        argument_spec = dict(
            category = dict(required=True, type='str', default=None),
            command = dict(required=True, type='str', default=None),
            ibmcip = dict(required=True, type='str', default=None),
            ibmcuser = dict(required=False, type='str', default=None),
            ibmcpswd = dict(required=False, type='str', default=None),
            fileserveruser = dict(required=False, type='str', default=None),
            fileserverpswd = dict(required=False, type='str', default=None),
            extraparam = dict(required=False, type='str', default=None)
        ),
        supports_check_mode=False
    )

    params = module.params
    category = params['category']
    command  = params['command']

    # Build initial URI
    root_uri = ''.join(["https://%s" % params['ibmcip'], "/redfish/v1"])

    # Disable insecure-certificate-warning message
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    IBMC_INFO = { 'ip'   : params['ibmcip'],
                   'user' : params['ibmcuser'],
                   'pswd' : params['ibmcpswd']
                 } 
    
    createSession(IBMC_INFO,60)
    systemNumber = getSystemUri(IBMC_INFO, root_uri + "/Managers", 10)
    number = systemNumber.split("/")[4]
    
    chassis_uri  = "/Chassis/" + number 
    manager_uri  = "/Managers/" + number
    eventsvc_uri = "/EventService"
    system_uri = "/Systems/" + number
    # Execute based on what we want
    try:
        if category == "Inventory":
            ret = getInventory(command, IBMC_INFO, root_uri, system_uri, chassis_uri, manager_uri)
            result = {'result': True, 'msg':ret}
        elif category == "Power":
            result = managePower(command, IBMC_INFO, root_uri, system_uri)
        elif category == "DeployOS":
            result = deployOsProcess(command, IBMC_INFO, root_uri, system_uri, manager_uri)
        elif category == "DeployOsBySp":
            result = deploySPOSProcess(command, IBMC_INFO, root_uri, system_uri, manager_uri)
        elif category == "CfgRaid":
            result = cfgRaid(command, IBMC_INFO, root_uri, system_uri)
        elif category == "ModifyRaid":
            result = modifyRaid(command,IBMC_INFO,root_uri,system_uri)  	      
        elif category == "DelLD":
            result = deletAllLd(command, IBMC_INFO, root_uri, system_uri)
        elif category == "DelALD":
            result = deletALD(command, IBMC_INFO, root_uri, system_uri)    
        elif category == "UpdateFW":
            result = updateFW(command, IBMC_INFO, root_uri, system_uri)
        elif category == "SetBootDevice":
            result = setBootDevice(command, IBMC_INFO, root_uri, system_uri)
        elif category == "ConfigBMC":
            result = configBmc(command, IBMC_INFO, root_uri, manager_uri)
        elif category == "CfgSnmpTrap":
            result = cfgTrap(command, params['extraparam'],IBMC_INFO, root_uri, manager_uri)
        elif category == "Profile":
            result = serverProfile(command, IBMC_INFO, root_uri, manager_uri)
        elif category == "GetRaidInfo":
            result = getRaidInfo( IBMC_INFO, root_uri, system_uri)
        elif category == "ConfigNTP":
            result = configNTP(command, IBMC_INFO, root_uri, manager_uri)
        elif category == "UpgradeFwBySp":
            result = upgradeFwBySp(params['extraparam'],params['fileserveruser'],params['fileserverpswd'],IBMC_INFO,root_uri,system_uri,manager_uri )
        elif category =="GetFwInfo":
            result = getFWInfo(IBMC_INFO,root_uri,system_uri,manager_uri)  	
        else:
            result = {'result': False,'msg':"Invalid Category"}
    except Exception, e:
        result = {'result': False,'msg':str(e)}
    finally:
        deleteSession(IBMC_INFO,10)
        params['ibmcpswd']="******"


    if result['result'] == True:
        del result['result']               
        module.exit_json(result=result['msg'])
    else:
        module.fail_json(msg=result['msg'])


if __name__ == '__main__':
    main()
    
