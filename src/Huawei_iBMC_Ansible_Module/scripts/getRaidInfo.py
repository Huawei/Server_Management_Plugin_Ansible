#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Huawei.
#
# This file is part of Ansible
#

import os
import json
import re
import sys
import time
import commands
import base64
import platform
import string
import logging, logging.handlers
from datetime import datetime

sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from powerManage import *

global token


'''
#==========================================================================
# @Method: get raid info 
# @command: 
# @Param: ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def writeRaidInfo(ibmc, root_uri, system_uri):
    raidInfo_uri = system_uri + "/Storages/RAIDStorage0/Volumes"
    token = getToken()
    result = None
    msg = '' 
 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + raidInfo_uri
    fileName = ibmc['ip'] + "_raidInfo.json"
    
    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            Members = r['Members']
        for Member in Members:
            uri = "https://" + ibmc['ip'] + Member[u'@odata.id']
            rp = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
            if rp.status_code != 200:
                return (False,"get raid info failed,error code:%s" %str(rp.status_code))
            with open('/etc/ansible/ansible_ibmc/report/' + fileName ,"w") as fd:
                json.dump(rp.json(), fd, indent=1)
        return True,'get raid info Successfully!'
    except Exception,e:
        (result,msg) = False,"get raid info failed!error info:%s" %str(e)
        return result,msg
        raise
    finally:
        fd.close()


'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def getRaidInfo(command, ibmc, root_uri, system_uri):
    rets = {'result':True,'msg': 'get raid info successfully!'}
    # before config raid, make sure x86 is power on state!
    powerState = managePower('PowerState', ibmc, root_uri, system_uri)
    if powerState.find("On") == -1: 
        rets['msg'] = "the system is poweroff, make sure the system is power on , wait 5 mins and try it again!"
        return rets

    # get logic device info one by one
    try:
        (rets['result'],rets['msg']) = writeRaidInfo(ibmc, root_uri, system_uri)
    except Exception,e:
        rets['result'] = False
        rets['msg'] = "get logic device info failed,error info:" + str(e)
    finally:
        return rets

if __name__ == '__main__':
    main()
 
