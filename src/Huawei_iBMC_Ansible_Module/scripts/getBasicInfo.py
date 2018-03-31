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

LOG_FILE = "/etc/ansible/ansible_ibmc/log/inventoryLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/inventoryReport.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('inventoryLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)

report = logging.getLogger('inventoryReport')
report.addHandler(report_hander)
report.setLevel(logging.INFO)


'''
#==========================================================================
# @Method: get CPU Status
# @command: getCPUStatus
# @Param: command ibmc uri
# @date: 2017.12.27
#==========================================================================
'''
def getCPUStatus(IBMC_INFO, url, timeout):
    CPUState = "OK"
    CPUStatus = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        CPUCount = result[u'Members@odata.count']

        for i in range(0,CPUCount):
            Members = result[u'Members'][i][u'@odata.id']
            url = "https://" + IBMC_INFO['ip']  + Members
            response = sendGetRequest(IBMC_INFO, url, timeout)
            r = response.json()
            status = r[u'Status'][u'Health']
            if status == None:
                status = ""
            CPUName = r[u'Name']
            if CPUStatus == "":
                CPUStatus = CPUName + ":" + status
            else:
                CPUStatus = CPUStatus +   ";"    + CPUName + ":" + status
            
        if CPUStatus.find("Critical") > -1:
            CPUState = "Critical"
        elif CPUStatus.find("Warning") > -1:
            CPUState = "Warning"
        else:
            CPUState = "OK"
        return CPUState + "{" +  CPUStatus + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get CPU status failed! " + str(e))
        raise
        

'''
#==========================================================================
# @Method: get Memory Status
# @command: getMemoryStatus
# @Param: command ibmc uri
# @date: 2017.12.28
#==========================================================================
'''
def getMemoryStatus(IBMC_INFO, url, timeout):
    MemoryState = "OK"
    MemoryStatus = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        MemCount = result[u'Members@odata.count']

        for i in range(0,MemCount):
            Members = result[u'Members'][i][u'@odata.id']
            url = "https://" + IBMC_INFO['ip']  + Members
            response = sendGetRequest(IBMC_INFO, url, timeout)
            r = response.json()
            status = r[u'Status'][u'Health']
            if status == None:
                status = ""
            MemName = r[u'Name']
            if MemoryStatus == "":
                MemoryStatus = MemName + ":" + status
            else:
                MemoryStatus = MemoryStatus +   ";"    + MemName + ":" + status

        if MemoryStatus.find("Critical") > -1:
            MemoryState = "Critical"
        elif MemoryStatus.find("Warning") > -1:
            MemoryState = "Warning"
        else:
            MemoryState = "OK"
        return MemoryState + "{" +  MemoryStatus + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get Memory status failed! " + str(e))
        raise

'''
#==========================================================================
# @Method: get Disk Status
# @command: getDiskStatus
# @Param: command ibmc uri
# @date: 2017.12.28
#==========================================================================
'''
def getDiskStatus(IBMC_INFO, url, timeout):
    DiskState = "OK"
    DiskStatus = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        DiskCount = len(result[u'Links'][u'Drives'])

        for i in range(0,DiskCount):
            Members = result[u'Links'][u'Drives'][i][u'@odata.id']
            url = "https://" + IBMC_INFO['ip']  + Members
            response = sendGetRequest(IBMC_INFO, url, timeout)
            r = response.json()
            status = r[u'Status'][u'Health']
            if status == None:
                status = ""
            DiskName = r[u'Name']
            if DiskStatus == "":
                DiskStatus = DiskName + ":" + status
            else:
                DiskStatus = DiskStatus +   ";"    + DiskName + ":" + status

        if DiskStatus.find("Critical") > -1:
            DiskState = "Critical"
        elif DiskStatus.find("Warning") > -1:
            DiskState = "Warning"
        else:
            DiskState = "OK"
        return DiskState + "{" +  DiskStatus + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get Disk status failed! " + str(e))
        raise



'''
#==========================================================================
# @Method: get Fans Status
# @command: getFansStatus
# @Param: command ibmc uri
# @date: 2017.12.28
#==========================================================================
'''
def getFansStatus(IBMC_INFO, url, timeout):
    FansState = "OK"
    FansStatus = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        FansCount = len(result[u'Fans'])

        for i in range(0,FansCount):
            status = result[u'Fans'][i][u'Status'][u'Health']
            if status == None:
                status = ""
            FansName = result[u'Fans'][i][u'Name']
            if FansName == None:
                FansName = ""
            if FansStatus == "":
                FansStatus = FansName + ":" + status
            else:
                FansStatus = FansStatus +   ";"    + FansName + ":" + status

        if FansStatus.find("Critical") > -1:
            FansState = "Critical"
        elif FansStatus.find("Warning") > -1:
            FansState = "Warning"
        else:
            FansState = "OK"
        return FansState + "{" +  FansStatus + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get Fans status failed! " + str(e))
        raise

'''
#==========================================================================
# @Method: get Power Supplies Status
# @command: getPowerSuppliesStatus
# @Param: command ibmc uri
# @date: 2017.12.28
#==========================================================================
'''
def getPowerSuppliesStatus(IBMC_INFO, url, timeout):
    PSState = "OK"
    PSStatus = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        PSCount = len(result[u'PowerSupplies'])

        for i in range(0,PSCount):
            status = result[u'PowerSupplies'][i][u'Status'][u'Health']
            if status == None:
                status = ""
            PSName = result[u'PowerSupplies'][i][u'Name']
            if PSStatus == "":
                PSStatus = PSName + ":" + status
            else:
                PSStatus = PSStatus +   ";"    + PSName + ":" + status

        if PSStatus.find("Critical") > -1:
            PSState = "Critical"
        elif PSStatus.find("Warning") > -1:
            PSState = "Warning"
        else:
            PSState = "OK"
        return PSState + "{" +  PSStatus + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get Power Supplies status failed! " + str(e))
        raise

'''
#==========================================================================
# @Method: get RAID Card Version Status
# @command: getRaidCardVersion
# @Param: command ibmc uri
# @date: 2017.12.29
#==========================================================================
'''
def getRaidCardVersion(IBMC_INFO, url, timeout):
    RaidDriverVersions = ""
    RaidFwVersions = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        RAIDCount = result[u'Members@odata.count']

        for i in range(0,RAIDCount):
            raid_uri = result[u'Members'][i][u'@odata.id']
            if raid_uri.find("RAIDStorage") <= -1:
                continue
            request_uri = "https://" + IBMC_INFO[u'ip'] + raid_uri
            responses = sendGetRequest(IBMC_INFO,request_uri,timeout)
            r = responses.json()
            controllerCount = r[u'StorageControllers@odata.count']

            for j in range(0,controllerCount):
                RaidDriverVersion = r[u'StorageControllers'][j][u'Oem'][u'Huawei'][u'DriverInfo'][u'DriverVersion']
                RaidDriverName = r[u'StorageControllers'][j][u'Oem'][u'Huawei'][u'DriverInfo'][u'DriverName']
                RaidFwVersion = r[u'StorageControllers'][j][u'FirmwareVersion']
                if RaidDriverVersion is None:
                    RaidDriverVersion = ""
                if RaidDriverName is None:
                    RaidDriverName = ""
                if RaidFwVersion is None:
                    RaidFwVersion = ""

                if RaidDriverVersions == "":
                    RaidDriverVersions = RaidDriverName + " version:" + RaidDriverVersion
                else:
                    RaidDriverVersions = RaidDriverVersions + ";" + RaidDriverName + " version:" + RaidDriverVersion

                if RaidFwVersions == "":
                    RaidFwVersions = "controller" + str(j) + " version:" + RaidFwVersion
                else:
                    RaidFwVersions = RaidFwVersions + ";" + " controller" + str(j) + " version:" + RaidFwVersion

        return "Driver info:{" + RaidDriverVersions + "} Firmware info:{" +  RaidFwVersions + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get RAID info failed! " + str(e))
        raise

'''
#==========================================================================
# @Method: get NetAdapt Card Version
# @command: getNetAdaptVersion
# @Param: command ibmc uri
# @date: 2017.12.29
#==========================================================================
'''
def getNetAdaptVersion(IBMC_INFO, url, timeout):
    NetAdaptDriverVersions = ""
    NetAdaptFwVersions = ""

    try:
        response = sendGetRequest(IBMC_INFO,url,timeout)
        result = response.json()
        AdaptCount = result[u'Members@odata.count']

        for i in range(0,AdaptCount):
            adapt_uri = result[u'Members'][i][u'@odata.id']
            request_uri = "https://" + IBMC_INFO[u'ip'] + adapt_uri
            responses = sendGetRequest(IBMC_INFO,request_uri,timeout)
            r = responses.json()
            controllerCount = len(r[u'Controllers'])

            for j in range(0,controllerCount):
                NetAdaptDriverVersion = r[u'Oem'][u'Huawei'][u'DriverVersion']
                NetAdaptDriverName = r[u'Oem'][u'Huawei'][u'DriverName']
                NetAdaptFwVersion = r[u'Controllers'][j][u'FirmwarePackageVersion']
                if NetAdaptDriverVersion is None:
                    NetAdaptDriverVersion = ""
                if NetAdaptDriverName is None:
                    NetAdaptDriverName = ""
                if NetAdaptFwVersion is None:
                    NetAdaptFwVersion = ""

                if NetAdaptDriverVersions == "":
                    NetAdaptDriverVersions = NetAdaptDriverName + " version:" + NetAdaptDriverVersion
                else:
                    NetAdaptDriverVersions = NetAdaptDriverVersions + ";" + NetAdaptDriverName + " version:" + NetAdaptDriverVersion

                if NetAdaptFwVersions == "":
                    NetAdaptFwVersions = "controller" + str(j) + " version:" + NetAdaptFwVersion
                else:
                    NetAdaptFwVersions = NetAdaptFwVersions + ";" + " controller" + str(j) + " version:" + NetAdaptFwVersion

        return "Driver info:{" + NetAdaptDriverVersions + "} Firmware info:{" +  NetAdaptFwVersions + "}"

    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- get Networks Adapt info failed! " + str(e))
        raise


'''
#==========================================================================
# @Method: 获取日志信息
# @command: get_logs
# @Param: command ibmc uri
# @date: 2017.9.15
#==========================================================================
'''
def getLogs(command, IBMC_INFO, root_uri):
    if command == "GetSelog":
        response = sendGetRequest(IBMC_INFO, root_uri + manager_uri + "/Logs/Sel")
        result = response.json()
    elif command == "GetLclog":
        response = sendGetRequest(IBMC_INFO, root_uri + manager_uri + "/Logs/Lclog")
        result = response.json()
    else:
        result = "Invalid Option."
    return result

'''
#==========================================================================
# @Method: 获取硬件信息
# @command: get_inventory
# @Param: command ibmc uri
# @date: 2017.9.15
#==========================================================================
'''
def getInventory(command, IBMC_INFO, root_uri, system_uri, chassis_uri, manager_uri):
    try:
        if command == "ServerStatus":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'Status'][u'Health']
        elif command == "ServerModel":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'Model']
        elif command == "BiosVersion":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'BiosVersion']
        elif command == "CPLDVersion":
            boards_uri = "/Boards/chassisMainBoard"
            response = sendGetRequest(IBMC_INFO, root_uri + chassis_uri + boards_uri,10)
            data = response.json()
            result = data[u'CPLDVersion']
        elif command == "ServerManufacturer":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'Manufacturer']
        elif command == "ServerPartNumber":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'PartNumber']
        elif command == "SystemType":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'SystemType']
        elif command == "AssetTag":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'AssetTag']
        elif command == "MemoryGiB":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'MemorySummary'][u'TotalSystemMemoryGiB']
        elif command == "CPUModel":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri + "/Processors",10)
            data = response.json()
            CPUCount = data[u'Members@odata.count']
            result = ""
            for i in range(0,CPUCount):
                response = sendGetRequest(IBMC_INFO, root_uri + system_uri + "/Processors/"+str(i+1),10)
                data = response.json()
                if i != 0:
                    result = result + ";"
                if data[u'Model'] == None:
                    Model = ""
                else:
                    Model = data[u'Model']
                result = result + data[u'Name'] + ":" + Model
        elif command == "CPUHealth":
            cpu_uri = "/Processors"
            result = getCPUStatus(IBMC_INFO, root_uri + system_uri + cpu_uri, 10)
        elif command == "MemoryHealth":
            mem_uri = "/Memory"
            result = getMemoryStatus(IBMC_INFO, root_uri + system_uri + mem_uri, 10)
        elif command == "FansHealth":
            thermal_uri = "/Thermal"
            result = getFansStatus(IBMC_INFO, root_uri + chassis_uri + thermal_uri, 10)
        elif command == "PowerSuppliesHealth":
            ps_uri = "/Power"
            result = getPowerSuppliesStatus(IBMC_INFO, root_uri + chassis_uri + ps_uri, 10)
        elif command == "DiskHealth":
            result = getDiskStatus(IBMC_INFO, root_uri + chassis_uri, 10)
        elif command == "CPUCount":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'ProcessorSummary'][u'Count']
        elif command == "ConsumedWatts":
            response = sendGetRequest(IBMC_INFO, root_uri + chassis_uri + "/Power",10)
            data = response.json()
            result = data[u'PowerControl'][0][u'PowerConsumedWatts']
        elif command == "PowerState":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'PowerState']
        elif command == "SerialNumber":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'SerialNumber']
        elif command == "iBMCFirmwareVersion":
            response = sendGetRequest(IBMC_INFO, root_uri + manager_uri,10)
            data = response.json()
            result = data[u'FirmwareVersion']
        elif command == "RAIDCardVersion":
            storage_uri = "/Storages"
            result = getRaidCardVersion(IBMC_INFO, root_uri + system_uri + storage_uri,10)
        elif command == "NetWorksAdaptVersion":
            adapt_uri = "/NetworkAdapters"
            result = getNetAdaptVersion(IBMC_INFO, root_uri + chassis_uri + adapt_uri,10)
        elif command == "iBMCHealth":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            result = data[u'Status'][u'Health']
        elif command == "BootSourceOverrideMode":
            response = sendGetRequest(IBMC_INFO, root_uri + system_uri,10)
            data = response.json()
            datadict = data[u'Boot']
            if 'BootSourceOverrideMode' in datadict.keys():
                result = data[u'Boot'][u'BootSourceOverrideMode']
        else:
            result = "Invalid Command."

        log.info(IBMC_INFO['ip'] + " -- " + command + " " + str(result))
        if result == '' or result is None or len(str(result)) == 0:
            log.info(IBMC_INFO['ip'] + " -- " + command +  " result is null")
            result = " "

        return result
    except Exception,e:
        log.info(IBMC_INFO['ip'] + " -- " + command + " exception: " + str(e))
        raise
   
if __name__ == '__main__':
    main()
 
