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
import logging, logging.handlers
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
from commonLoger import *
EXPORT_URI = "/Actions/Oem/Huawei/Manager.ExportConfiguration"
IMPORT_URI = "/Actions/Oem/Huawei/Manager.ImportConfiguration"

LOG_FILE = "/etc/ansible/ansible_ibmc/log/serverProfile.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/serverProfile.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"serverProfile")

'''
#==========================================================================
# @Method: get task status
# @command: get task status
# @Param: info ibmc url
# @date: 2017.12.26
#==========================================================================
'''
def getTaskInfo(ibmc, root_uri, taskid):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + "/TaskService/Tasks/"+taskid
    payload = {}
    try:
        ret = request('GET',resource=uri,headers=headers,data=payload, tmout=300,ip=ibmc['ip'])
    except Exception,e:
        log.info("get task failed:" + str(e))
        raise

    return ret


'''
#==========================================================================
# @Method: export profile
# @command: Profile
# @Param: path ibmc url
# @date: 2017.12.26
#==========================================================================
'''
def exportProfile(filepath,ibmc,root_uri,manage_uri):
    uri = root_uri + manage_uri + EXPORT_URI
    token = getToken()

    headers = {'Content-Type': 'application/json','X-Auth-Token':token}
    playload = {'Type': 'URI', 'Content': filepath}

    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=60,ip=ibmc['ip'])
    except Exception,e:
        r = None
        log.info(ibmc['ip'] + " -- " + "export server profile failed:" + str(e))
        raise

    return r


'''
#==========================================================================
# @Method: import profile
# @command: serverProfile
# @Param: path ibmc url
# @date: 2017.12.26
#==========================================================================
'''
def importProfile(filepath,ibmc,root_uri,manage_uri):
    uri = root_uri + manage_uri + IMPORT_URI
    token = getToken()

    headers = {'content-type': 'application/json','X-Auth-Token':token}

    playload = {"Type":"URI","Content":filepath}

    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=60,ip=ibmc['ip'])
    except Exception,e:
        r = None
        log.info(ibmc['ip'] + " -- " + "import server profile failed:" + str(e))
        raise

    return r


'''
#==========================================================================
# @Method: server profile
# @command: serverProfile
# @Param: info ibmc url
# @date: 2017.12.26
#==========================================================================
'''
def serverProfile(filepath,ibmc,root_uri,manage_uri):
    rets = {'result':True,'msg': ''}
    token = getToken()

    command = filepath.split(';')[0].upper()
    path = filepath.split(';')[1]
    if path.find("@") == -1:
        filepath = path
    else:
        filepath = path.split('@')[1]

    try:
        if command == "IMPORT":
            r = importProfile(path,ibmc,root_uri,manage_uri)
        elif command == "EXPORT":
            r = exportProfile(path,ibmc,root_uri,manage_uri)
        else:
            report.info(ibmc['ip'] + " -- " + "unknown command:" + command + " plsease check the serverProfile.yml ")
            LOG.info(ibmc['ip'] + " -- " + "unknown command:" + command + " plsease check the serverProfile.yml ")
            rets['result'] = False
            rets['msg'] = "unknown command:" + command + " plsease check the serverProfile.yml "
            return rets
            
        code = r.status_code
        data = r.json()
        if code == 202:
            taskid = data['Id']
            while 1:
                time.sleep(1)
                ret = getTaskInfo(ibmc, root_uri, taskid)
                if ret is not None and ret.status_code == 200:
                    code = ret.status_code
                    data = ret.json()
                elif ret is not None:
                    log.info(ibmc['ip'] + " -- code is :" + ret.status_code + " 200,may be there are disconnect,you should wait for a moment!\n")
                    continue
                else:
                    log.info(ibmc['ip'] + " -- ret is None,may be there are disconnect,you should wait for a moment!\n")
                    continue

                ret = data[u'TaskState']
                percent = data[u'Oem'][u'Huawei'][u'TaskPercentage']
                log.info(ibmc['ip'] + " -- status:" +ret + " percent:" + str(percent))
                if ret == 'Running':
                    time.sleep(1)
                    continue
                elif ret == 'OK' or ret == 'Completed' or percent == '100%':
                    log.info(ibmc['ip'] + " -- " + command + ":" + filepath.split("/")[-1] + " successful! \n")
                    report.info(ibmc['ip'] + " -- " + command + ":" + filepath + " successful!")
                    rets['result'] = True
                    rets['msg'] = command + ":" + filepath.split("/")[-1] + " successful!"
                    break
                else:
                    log.info(ibmc['ip'] + " -- " + command + ":" + filepath.split("/")[-1] + " failed! \n")
                    report.info(ibmc['ip'] + " -- " + command + ":" + filepath.split("/")[-1] + " failed! \n")
                    rets['result'] = False
                    rets['msg'] = command + ":" + filepath + " failed: unknown error"
                    break
        else:
            report.info(ibmc['ip'] + " -- " + command + " profile " + filepath.split("/")[-1] + " failed!")
            log.info(ibmc['ip'] + " -- " + command + " profile " + filepath.split("/")[-1] + " failed!")
            rets['result'] = False
            rets['msg'] = command + ' failed! the error code is ' + str(code)

    except Exception, e:
        report.info(ibmc['ip'] + " -- " + command + " profile failed!" + str(e))
        log.info(ibmc['ip'] + " -- " + command + " profile failed!" + str(e) + " \n")
        rets['result'] = False
        rets['msg'] = command + ' profile failed! ' + str(e)
        raise

    return rets

   
if __name__ == '__main__':
    main()
 
