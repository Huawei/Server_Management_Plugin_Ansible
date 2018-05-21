#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Huawei.
#
# This file is part of Ansible
#

import os
import json
import sys
import time
import logging, logging.handlers
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
from commonLoger import *
LOG_FILE = "/etc/ansible/ansible_ibmc/log/pmLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/pmReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"pmReport")


'''
#==========================================================================
# @Method: PowerOn,PowerOff,ForceRestart,GracefulShutdown,ForcePowerCycle,Nmi
# @Param: command ibmc url
# @date: 2017.9.16
#==========================================================================
'''
def managePower(command, IBMC_INFO, root_uri, system_uri):
    headers = {'content-type': 'application/json'}
    reseturi = root_uri + system_uri + "/Actions/ComputerSystem.Reset"
    rets = {'result':True,'msg': ''}

    if command == "PowerState":
        try:
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            if response.status_code == 200:
                data = response.json()
                result = data[u'PowerState']
                return result
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"get system power state failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"get system power state failed!")
                rets['result'] = False
                rets['msg'] = "get system power state failed!"
        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"get system power state failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"get system power state failed!")
            rets['result'] = False
            rets['msg'] = "get system power state failed!"
            raise

    elif command == "PowerOn":
        payload = {'ResetType': 'On'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system power on successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system power on successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system power on failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system power on failed!")
                rets['result'] = False
                rets['msg'] = "set system power on failed!"
        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system power on failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system power on failed!")
            rets['result'] = False
            rets['msg'] = "set system power on failed!"
            raise

    elif command == "PowerOff":
        payload = {'ResetType': 'ForceOff'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system power off successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system power off successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system power off failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system power off failed!")
                rets['result'] = False
                rets['msg'] = "set system PowerOff failed!"

        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system power off failed!" + str(e)+ "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system power off failed!" + str(e))
            rets['result'] = False
            rets['msg'] = "set system PowerOff failed!"
            raise

    elif command == "ForceRestart":
        payload = {'ResetType': 'ForceRestart'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system force restart successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system force restart successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system force restart failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system power restart failed!")
                rets['result'] = False
                rets['msg'] = "set system force restart failed!"

        except Exception, e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system force restart failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system force restart failed!")
            rets['result'] = False
            rets['msg'] = "set system ForceRestart failed!"
            raise

    elif command == "GracefulShutdown":
        payload = {'ResetType': 'GracefulShutdown'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown failed!")
                rets['result'] = False
                rets['msg'] = "set system GracefulShutdown failed!"

        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system GracefulShutdown failed!")
            rets['result'] = False
            rets['msg'] = "set system GracefulShutdown failed!"
            raise

    elif command == "ForcePowerCycle":
        payload = {'ResetType': 'ForcePowerCycle'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle failed!")
                rets['result'] = False
                rets['msg'] = "set system ForcePowerCycle failed!"

        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system ForcePowerCycle failed!")
            rets['result'] = False
            rets['msg'] = "set system ForcePowerCycle failed!"
            raise

    elif command == "Nmi":
        payload = {'ResetType': 'Nmi'}
        try:
            data = sendPostRequest(IBMC_INFO, reseturi, payload, headers)
            result = data.status_code
            if result == 200:
                log.info(IBMC_INFO['ip'] + " -- " +"set system Nmi successful!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system Nmi successful!")
                rets['result'] = True
                rets['msg'] = "Successful"
            else:
                log.info(IBMC_INFO['ip'] + " -- " +"set system Nmi failed!" + "\n")
                report.info(IBMC_INFO['ip'] + " -- " +"set system Nmi failed!")
                rets['result'] = False
                rets['msg'] = "set system Nmi failed!"

        except Exception,e:
            log.info(IBMC_INFO['ip'] + " -- " +"set system Nmi failed!" + "\n")
            report.info(IBMC_INFO['ip'] + " -- " +"set system Nmi failed!")
            rets['result'] = False
            rets['msg'] = "set system Nmi failed!"
            raise



    else:
        log.info(IBMC_INFO['ip'] + " -- " +"unsupport for this command, please check the PowerManage.yml again!" + "\n")
        report.info(IBMC_INFO['ip'] + " -- " +"unsupport for this command, please check the PowerManage.yml again!!")
        rets['result'] = False
        rets['msg'] = "unsupport for this command, please check the PowerManage.yml again!!"

    return rets

   
if __name__ == '__main__':
    main()
 
