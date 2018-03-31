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

LOG_FILE = "/etc/ansible/ansible_ibmc/log/updateFwLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/updateFwReport.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('updateFwLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)

report = logging.getLogger('updateFwReport')
report.addHandler(report_hander)
report.setLevel(logging.INFO)


'''
#==========================================================================
# @Method: get taks status
# @command: set_bootdevice
# @Param: device ibmc url
# @date: 2017.10.21
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
# @Method: update fw
# @command: set_bootdevice
# @Param: device ibmc url
# @date: 2017.10.21
#==========================================================================
'''
def update(filepath,ibmc,root_uri,system_uri):
    uri = root_uri + "/UpdateService/Actions/UpdateService.SimpleUpdate"
    token = getToken()

    headers = {'content-type': 'application/json','X-Auth-Token':token}
    
    protocol = filepath.split(':')[0].upper()
    playload = {"ImageURI":filepath,"TransferProtocol":protocol}

    log.info(ibmc['ip'] + " -- protocol:" + protocol + " filepath:" + filepath.split("/")[-1])

    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=60,ip=ibmc['ip']) 
    except Exception,e:
        r = None
        log.info(ibmc['ip'] + " -- " + "update failed:" + str(e))
        raise
    
    return r

'''
#==========================================================================
# @Method: update fw
# @command: 
# @Param: filepath ibmc uri 
# @date: 2017.10.24
#==========================================================================
'''
def updateFW(filepath,ibmc,root_uri, system_uri):

    rets = {'result':True,'msg': ''}
    try: 
        ret = update(filepath,ibmc,root_uri, system_uri)
        log.info(ibmc['ip'] + " -- " +"ret:" + str(ret))
        code = ret.status_code
        data = ret.json()
        log.info(ibmc['ip'] + " -- " +str(data) + " code:" + str(code) )
        if code == 202:
            taskid = data['Id']
            while 1:
                time.sleep(1)
                ret = getTaskInfo(ibmc, root_uri, taskid)
                if ret is not None and ret.status_code == 200:
                    code = ret.status_code
                    data = ret.json()
                elif ret is not None:
                    log.info(ibmc['ip'] + " -- " +"code is :" + ret.status_code + " 200,may be there are disconnect,you should wait for a moment!\n")
                    continue
                else:
                    log.info(ibmc['ip'] + " -- " +"ret is None,may be there are disconnect,you should wait for a moment!\n")
                    continue

                ret = data[u'TaskState']
                percent = data[u'Oem'][u'Huawei'][u'TaskPercentage']
                log.info(ibmc['ip'] + " -- status:" +ret + " percent:" + str(percent))
                if ret == 'Running':
                    time.sleep(1)
                    continue
                elif ret == 'OK' or ret == 'Completed' or percent == '100%':
                    log.info(ibmc['ip'] + " -- " +"update " + filepath.split("/")[-1] + " successful! \n")
                    report.info(ibmc['ip'] + " -- " +"update " + filepath.split("/")[-1] + " successful!")
                    rets['result'] = True
                    rets['msg'] = "update successful!"
                    break
                else:
                    log.info(ibmc['ip'] + " -- " +"update " + filepath.split("/")[-1] + " failed! \n")
                    report.info(ibmc['ip'] + " -- " +"update " + filepath + " failed! \n")
                    rets['result'] = False 
                    rets['msg'] = "update failed: unknown error"
                    break
                
        else:
            log.info(ibmc['ip'] + " -- " +"updata failed: " + data[u'error'][u'@Message.ExtendedInfo'][0][u'Message'] + "\n")
            report.info(ibmc['ip'] + " -- " +" updata failed: " + data[u'error'][u'@Message.ExtendedInfo'][0][u'Message'] + "\n")
            rets['result'] = False
            rets['msg'] = " updata failed: " + data[u'error'][u'@Message.ExtendedInfo'][0][u'Message']
        return rets
    except Exception,e:
        log.info(ibmc['ip'] + " -- " +" updata failed: " + str(e) + "\n")
        report.info(ibmc['ip'] + " -- " +" updata failed "+ str(e) + "\n")
        rets['result'] = False 
        rets['msg'] = ":update failed!" + str(e)
        raise

if __name__ == '__main__':
    main()

