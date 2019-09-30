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
REQUEST_Ok=200
global token
from commonLoger import ansibleGetLoger
LOG_FILE = "/etc/ansible/ansible_ibmc/log/getRaidInfo.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/getRaidInfoReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"getRaidInfo")

def ApiGetStorages(ibmc,root_uri,system_uri):
    ret = {"result":True , 'msg':"ApiGetStorages successfully!","storgesInfo":{}}
    uri = root_uri + system_uri +"/Storages"
    log.info("uri="+str(uri))
    token = getToken() 
    headers = {'X-Auth-Token':token} 
    r=request('GET',resource=uri, headers=headers,data=None,tmout=30,ip=ibmc["ip"])
    if r.status_code==REQUEST_Ok:
        ret["storgesInfo"].update(r.json())
        return ret
    else :
        ret["result"]=False
        ret["msg"]="ApiGetStorages failed"
        log.error(str(r.json()))
        return ret 


'''
#==========================================================================
# @Method: getRaidInfo
# @command: 
# @Param: filepath ibmc url
# @date: 2018.4.20
#==========================================================================
'''
def getRaidInfo( ibmc, root_uri, system_uri):
    rets = {'result':True,'msg': 'get raid info successfully!'}
    strAllMsg =''
    # before config raid, make sure x86 is power on state!
    powerState = managePower('PowerState', ibmc, root_uri, system_uri)
    if powerState.find("On") == -1: 
        rets['result'] =False
        rets['msg'] = str(ibmc["ip"])+"get raid info failed! the system is poweroff, make sure the system is power on , wait 5 mins and try it again!"
        return rets
    allStorgeInfo={}  
    r=ApiGetStorages(ibmc,root_uri,system_uri)   
    if r["result"] == True:
        for members in r["storgesInfo"]["Members"]:
            if not "RAIDStorage" in members["@odata.id"]:
                continue
            tmpDis={members["@odata.id"]:{}} 
            allStorgeInfo.update(tmpDis)
    else:
        rets['result'] =False
        rets['msg'] = str(ibmc["ip"])+"get raid info failed! get Strorages failed!"
        log.error(str(ibmc["ip"])+"ApiGetStorages error"+r['msg'])
        report.error(str(ibmc["ip"])+" getRaidInfo failed:  ApiGetStorages error"+r['msg'])
        return rets
    try:
        for key ,value  in  allStorgeInfo.items(): 
            uri = key
            strAllMsg=strAllMsg+"===========================================================\n"
            strAllMsg=strAllMsg+str(key)+":\n" 
            token = getToken() 
            headers = {'X-Auth-Token':token} 
            r = request('GET',resource="https://"+str(ibmc["ip"])+uri, headers=headers,data=None,tmout=30,ip=ibmc["ip"])
            if r.status_code == REQUEST_Ok:
                value.update(r.json())
                strAllMsg=strAllMsg+"raidmodle:"+str(value["StorageControllers"][0]["Model"])+"\n"
                unconfigDriver= value["Drives"]           

                value["raidinfo"]={}
                value["volumesinfo"]={}
                value["driverinfo"]={}
                #get raininfo  hardware info
                raidinfoUri = value["StorageControllers"][0]["Oem"]["Huawei"]["AssociatedCard"]["@odata.id"]
                r =  request('GET',resource="https://"+str(ibmc["ip"])+raidinfoUri, headers=headers,data=None,tmout=30,ip=ibmc["ip"])
                if r.status_code == REQUEST_Ok:
                    model= value["StorageControllers"][0]["Model"]
                    tmpKey=str(raidinfoUri)+"--"+str(model)
                    tmpdic={str(raidinfoUri)+"--"+str(model):r.json()}
                    value["raidinfo"].update(tmpdic)       
                else:
                    rets['result'] =False
                    rets['msg'] = "get raid info failed! get raid hardwareInfo  failed!"
                    log.error(str(ibmc["ip"])+"get volumes failed "+ str(r.json() ))
                    report.error(str(ibmc["ip"])+"getRaidInfo failed: get volumes failed "+str(r.json() ))
                    return rets     
                #get volumesinfo
                volumesinfoUriDic=value["Volumes"] 
                r= request('GET',resource="https://"+str(ibmc["ip"])+volumesinfoUriDic["@odata.id"], headers=headers,data=None,tmout=30,ip=ibmc["ip"])
                if r.status_code == REQUEST_Ok:
                    value["volumesinfo"][volumesinfoUriDic["@odata.id"]]=r.json()
                    for eachVolumeDis in   value["volumesinfo"][volumesinfoUriDic["@odata.id"]]["Members"]:
                        r= request('GET',resource="https://"+str(ibmc["ip"])+str(eachVolumeDis["@odata.id"]), headers=headers,data=None,tmout=30,ip=ibmc["ip"])                      
                        if  r.status_code == REQUEST_Ok:
                            strAllMsg=strAllMsg+"-"+str(eachVolumeDis["@odata.id"]).split("/")[8]+":\n"
                            strAllMsg=strAllMsg+"--raidLevel:"+r.json()["Oem"]["Huawei"]["VolumeRaidLevel"]+"\n"
                            strAllMsg=strAllMsg+"--drivers:\n"
                            for eachdriver in r.json()["Links"]["Drives"]:
                                if eachdriver=={} or eachdriver is None:
                                    continue
                                strAllMsg=strAllMsg+"---"+eachdriver["@odata.id"].split("/")[6]+"\n" 
                                if unconfigDriver != []:
                                    indexForDel =None
                                    for i in range(len(unconfigDriver)): 
                                        if  unconfigDriver[i]["@odata.id"]==eachdriver["@odata.id"] :
                                            indexForDel = i
                                    if indexForDel is not None:
                                        unconfigDriver.pop(indexForDel) 
                            value["volumesinfo"][volumesinfoUriDic["@odata.id"]][eachVolumeDis["@odata.id"]] =r.json()
                        else :
                            rets['result'] =False
                            rets['msg'] = "get raid info failed! get eachvolume failed!"
                            log.error( str(ibmc["ip"])+"parse each volume failed "+str(r.json() ))
                            report.error(str(ibmc["ip"])+" getRaidInfo failed: parse each volume failed "+str(r.json() ))
                            return rets     
                else:
                    rets['result'] =False
                    rets['msg'] = "get raid info failed! get volumes hardwareInfo  failed!"
                    log.error(str(ibmc["ip"])+"parse volumesinfo failed "+ str(r.json() ))
                    report.error(str(ibmc["ip"])+" getRaidInfo failed: parse volumesinfo failed "+str(r.json() ))
                    return rets
                #get driverinfo     
                driveInfoUriList=value["Drives"]
                for eachDrive in driveInfoUriList:
                    r=  request('GET',resource="https://"+str(ibmc["ip"])+eachDrive["@odata.id"], headers=headers,data=None,tmout=30,ip=ibmc["ip"])
                    if  r.status_code == REQUEST_Ok:
                        value["driverinfo"][eachDrive["@odata.id"]]=r.json()
                    else:
                        rets['result'] =False
                        rets['msg'] = str(ibmc["ip"])+"get raid info failed! get drive hardwareInfo  failed!"
                        log.error( str(ibmc["ip"])+"get driverinfo error :"+str(r.json() ))
                        report.error( str(ibmc["ip"])+" getRaidInfo failed: get driverinfo error")
                        return rets 
                strAllMsg=strAllMsg+"-unconfigDrivers:\n"
                if unconfigDriver !=[] or unconfigDriver is not None:
                    for eachdriver in unconfigDriver:
                        tmpDriverName= eachdriver["@odata.id"].split("/")[6]
                        strAllMsg=strAllMsg+"--"+tmpDriverName+"\n"
                else:
                    strAllMsg=strAllMsg+"None\n"                 
            else :
                rets['result'] =False
                rets['msg'] =str(ibmc["ip"])+ "get raid info failed! get raid failed!"
                log.error( str(ibmc["ip"])+ "parse storage raidinfo failed"+str(r.json() ))
                report.error(str(ibmc["ip"])+"getRaidInfo failed: parse storage raidinfo failed"+str(r.json() ))
                return rets 
    except Exception ,e:
       log.error( str(ibmc["ip"])+"parse raid info exception :"+str(e) )
       rets['result'] =False
       rets['msg'] =str(ibmc["ip"])+" getRaidInfo failed: get raid info exception"+str(e)
       return rets 
       
    fileName= str(ibmc['ip'])+"_raidInfo.json" 
    jsonfile=None
    try:
       jsonfile = open ( '/etc/ansible/ansible_ibmc/report/'+fileName,"w")
       if jsonfile is not None :
          json.dump(allStorgeInfo,jsonfile,indent=4) 
    except Exception ,e:
       log.error( str(ibmc["ip"])+"write json exception :"+str(e) )
    finally:
       if jsonfile is not None:
           jsonfile.close()
   
    rets['result'] =True
    rets['msg'] =str(ibmc["ip"])+ " get raid info successfully, totalInfo:\n  "+strAllMsg+"for more info please refer to /etc/ansible/ansible_ibmc/report/%s \n"%fileName
    report.info(str(ibmc["ip"])+" get raid info successfully, totalInfo:\n  "+strAllMsg+"for more info please refer to /etc/ansible/ansible_ibmc/report/%s \n"%fileName)
    return rets    
if __name__ == '__main__':
    main()
 
