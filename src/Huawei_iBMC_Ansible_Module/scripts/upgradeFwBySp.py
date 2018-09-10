#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2018, Huawei.
# Author: xueweihong
# Date: 20180417
# This file is 
# part of Ansible
import json
import re
import sys
import time
import commands
import base64
import platform
import subprocess
import string
import ConfigParser
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from powerManage import *
from cfgBmc import *
from commonLoger import ansibleGetLoger
from spRedfishAPI import *
LOG_FILE = "/etc/ansible/ansible_ibmc/log/upgradFwBySp.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/upgradFwBySpReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"upgradFwBySp")
CHECK_INTERVAL=6
#total time= 6s *20
WAIT_TRANFILE_TIME = 20
#total time= 6s *100
WATT_UPGRADE_RES = 150
#totall 900s
WAIT_SPSTART =9
KEEP_CONNECT_INTERVAL=100

def getConfig(configPath):
    list=[]
    file=None
    try:
        file=open(configPath)
        parser= ConfigParser.ConfigParser()  
        parser.readfp(file)
        for section in parser.sections():
            configDate={}
            for (key, value) in parser.items(section):
                configDate[key] = value
            list.append(configDate)
    except Exception ,err:
        log.error(" -- GetConfig  exception : "+str(err))  
    finally:
        if file is not None:
           file.close()     
        return list 

def getfileName(urL):
    tmplist=urL.split("/")
    if tmplist ==[] or tmplist is None:
        return ""
    else :
        return  tmplist[len(tmplist)-1]          

def spUpgradeFwProcess (filepath,fileserveruser,fileserverpswd,ibmc,root_uri, system_uri, manager_uri):
    rets = {'result':True,'msg': ''} 
    upgradeId="1"
    ret = managePower("PowerOff", ibmc, root_uri, system_uri)
    if ret['result'] == True:
        log.info(ibmc['ip'] + " -- ForceOff system successfully!")
    else:
        log.error(ibmc['ip'] + " -- ForceOff  system failed!")
        report.error(ibmc['ip'] + " -- upgarde Fw failed! ForceOff system failed!")
        rets['result'] = False
        rets['msg'] = "ForceOff system failed!"
        return rets
    ret = spApiGetFwUpdateId( ibmc, root_uri, manager_uri )
    if ret['result'] == True:
        log.info(ibmc['ip'] + " -- GetFwUpdateId  successfully!")
        if ret["updateidlist"]!=[] or ret["updateidlist"]!=None: 
            upgradeId=str(ret["updateidlist"][0]+1)
        else:
            log.error(ibmc['ip'] + " --GetFwUpdateId failed!")
            report.error(ibmc['ip'] + " -- upgarde Fw failed! GetFwUpdateId failed!")
            rets['result'] = False
            rets['msg'] = "GetFwUpdateId failed!"
            return rets         
    else:
        log.error(ibmc['ip'] + " --GetFwUpdateId failed!")
        report.error(ibmc['ip'] + " -- upgarde Fw failed! GetFwUpdateId failed!")
        rets['result'] = False
        rets['msg'] = "GetFwUpdateId failed!"
        return rets
    resultdis={}   
    configList = getConfig(filepath)
    if configList != []:    
        for eachitems in configList:
            itemslist=eachitems["imageurl"].split(":") 
            if  itemslist[1].startswith("//"):
                itemslist[1]= itemslist[1].lstrip("//")   
            if "NFS" in itemslist[0].upper():
                fwfileuri=itemslist[0]+"://"+itemslist[1]
                fwsignaluri=fwfileuri+".asc"           
            else:
                fwfileuri=itemslist[0]+"://"+fileserveruser +":"+fileserverpswd+"@"+itemslist[1]
                fwsignaluri=fwfileuri+".asc"
            tmpfilename=getfileName(eachitems["imageurl"])
            resultdis[tmpfilename]= "inited"
            ret = spApiSetFwUpgrade( ibmc, root_uri, manager_uri, fwfileuri,\
             fwsignaluri,updateId=upgradeId)
            if ret['result'] == True:
                log.info(ibmc['ip'] + " -- spApiSetFwUpgrade  successfully!")        
            else:
                resultdis[tmpfilename] = "failed"
                log.error(ibmc['ip'] + " --spApiSetFwUpgrade failed!") 
                report.error(ibmc['ip'] + " -- upgarde Fw failed! spApiSetFwUpgrade failed!")
                continue 
            #check files has tranfer to bmc 
            for i in range(WAIT_TRANFILE_TIME):
                time.sleep(CHECK_INTERVAL)
                ret=spApiGetFWSource ( ibmc, root_uri, manager_uri,updateId=upgradeId)
                if  ret['result']  == True:
                    filelist=ret["SourceInfo"]["FileList"]
                    if filelist ==[] or filelist==None :
                        continue
                    else :
                        filename =getfileName(eachitems["imageurl"])
                        if filename in filelist:
                            log.info(ibmc['ip'] + " -- spApiGetFWSource  successfully!") 
                            break
                if i == (WAIT_TRANFILE_TIME-1):
                    resultdis[tmpfilename] = "failed"
                    log.error(ibmc['ip'] + " --transfile  failed")
 
    else:
        log.error(ibmc['ip'] + " --getconfig failed!")
        report.error(ibmc['ip'] + " -- upgarde Fw failed! getconfig failed!")
        rets['result'] = False
        rets['msg'] = "getconfig failed!"
        return rets  
    if "inited" not in resultdis.values():
        log.error(ibmc['ip'] + " --set upgrade failed!")
        report.error(ibmc['ip'] + " -- upgarde Fw failed! set upgrade failed!")
        rets['result'] = False
        rets['msg'] = "setupgrade  failed!"+str(resultdis) 
        return rets     
    #start sp to  upgrade
    ret =  spAPISetSpService(ibmc, root_uri, manager_uri, spEnable=True )  
    if ret['result'] == True:
        log.info(ibmc['ip'] + " -- spAPISetSpService  successfully!")
    else :   
        time.sleep(CHECK_INTERVAL)    
        ret =  spAPISetSpService(ibmc, root_uri, manager_uri, spEnable=True )
        if ret['result']  == True: 
            log.info(ibmc['ip'] + " -- spAPISetSpService again successfully!")
        else :
            log.error(ibmc['ip'] + " -- spAPISetSpService again failed!")     
            report.error(ibmc['ip'] + " -- spAPISetSpService again failed!")
            rets['result'] = False
            rets['msg'] = "spAPISetSpService failed!"
            return rets 
    #power on 
    ret = managePower("PowerOn", ibmc, root_uri, system_uri)
    if ret['result'] == True:
        log.info(ibmc['ip'] + " -- poweron system successfully!")
    else :
        log.error(ibmc['ip'] + " -- poweron  system failed!")
        report.error(ibmc['ip'] + " -- upgarde Fw failed! poweron system failed!")
        rets['result'] = False
        rets['msg'] = "poweron system failed!"
        return rets 
    #wait sp start and keep connect 
    for i in range(WAIT_SPSTART):
        time.sleep(KEEP_CONNECT_INTERVAL)
        ret=spApiGetResultInfo(ibmc,root_uri,manager_uri,resultId=upgradeId)
        log.info(ibmc['ip'] +" waiting sp start ...")
        # try:
            # if ret['result'] == True:
                # if "Upgrade"in ret["resultInfo"].keys():
                    # log.info(ibmc['ip'] +" sp has start")
                    # break;
                # else:
                    # if  i == WAIT_SPSTART-1 :
                        # log.info( ibmc['ip'] +" wait sp start time out !")             
            # else :
                # log.info(ibmc['ip'] +"GetResultInfo error")
                # continue
        # except:
            # log.info(ibmc['ip'] +"GetResultInfo except")  
            # continue             
    # check update result

    for i in range(len(configList)*WATT_UPGRADE_RES): 
        time.sleep(CHECK_INTERVAL)
        ret = spApiGetResultInfo(ibmc,root_uri,manager_uri,resultId=upgradeId)
        if ret['result'] == True:
            try:
                if  "100" in ret["resultInfo"]["Upgrade"]["Progress"]:
                    resultInfoList= ret["resultInfo"]["Upgrade"]["Detail"]
                else:
                    log.info(ibmc['ip'] +" upgrade has not finished")
                    continue
                for eachitems in configList:
                    filename =getfileName(eachitems["imageurl"])
                    for eachdis in resultInfoList:
                        if  filename in eachdis["Firmware"] :
                            resultdis[filename] = eachdis["Status"]
                            if eachdis["Status"]!="upgraded" :
                                log.error (filename+ " upgrade failed  : "+ str(eachdis["Description"]) )
                                report.error (filename+ " upgrade failed  : "+ str(eachdis["Description"] )) 
                            break
            except:
                log.info(ibmc['ip'] +" have got  no upgrade result ")

            #result is ok 
            if (not "inited" in  resultdis.values() ) and (resultdis != {}):
                if  "failed" in  resultdis.values():
                    rets['result'] = False
                    log.error(ibmc['ip'] + " -- upgrade failed "+str( resultdis))
                    report.error(ibmc['ip'] + " -- upgrade failed"+str( resultdis))
                else :
                    rets['result'] = True 
                    log.info(ibmc['ip'] + " -- upgrade successfully ")
                    report.info(ibmc['ip'] + " -- upgrade successfully")   
                rets['msg'] = "check result finish ! result " + str (resultdis )  
                return rets                       
        else :
            log.error(ibmc['ip'] + " -- spApiGetResultInfo  system failed!")
            continue

    log.error(ibmc['ip'] + " -- check result timeout ")
    report.error(ibmc['ip'] + " -- check result timeout")
    rets['result'] = False
    rets['msg'] = ibmc['ip']+"check result timeout!"
    return rets

def getFWInfo(ibmc,root_uri, system_uri, manager_uri):
    LOG_FILE = "/etc/ansible/ansible_ibmc/log/getFwinfo.log"
    REPORT_FILE = "/etc/ansible/ansible_ibmc/report/getFwinfoReport.log"
    log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"getFwinfo")
    rets = {'result':True,'msg': ''} 
    ret = spApiGetFwInfo (ibmc,root_uri,manager_uri)
    if ret["result"] == True:
        if ret["fwInfo"] ==[] or   ret["fwInfo"]== None:
            rets['result'] = False
            rets['msg'] = "get fwInfo failed "
            return rets
        msg= ''
        try:   
            for eachFw in ret["fwInfo"]:
                msg=msg+"===============================================\n"
                msg=msg+"DeviceName:"+eachFw["DeviceName"]+"\n"
                msg=msg+"Manufacturer:"+eachFw["Controllers"][0]["Manufacturer"]+"\n"
                msg=msg+"Model:" +eachFw["Controllers"][0]["Model"]+"\n"
                msg=msg+"FirmwareVersion:"+eachFw["Controllers"][0]["FirmwareVersion"]+"\n"
        except Exception, err:
            log.error(  ibmc['ip']+"parse fwInfo exceptiom :"+str(err) )
        FWInfoDic={"fwinfo":ret["fwInfo"]}
        fileName= str(ibmc['ip'])+"fwInfo.json" 
        jsonfile=None
        try:
            jsonfile = open ( '/etc/ansible/ansible_ibmc/report/'+fileName,"w")
            if jsonfile is not None :
                json.dump(FWInfoDic,jsonfile,indent=4) 
        except Exception ,e:
            log.error(  ibmc['ip']+" write json exception :"+str(e) )
        finally:
            if jsonfile is not None:
                jsonfile.close()  
        rets["result"]=True
        rets["msg"]=msg+" for more info please refer to " +fileName
        report.info( ibmc['ip']+' get fwinfo success \n'+msg)
        log.info( ibmc['ip']+' get fwinfo success \n'+msg)
              
    else :
        rets['result'] = False
        rets['msg'] = ibmc['ip']+ " get fwInfo failed,  make sure you have poweroff SP"
        log.error( ibmc['ip']+" get fwInfo failed,  make sure you have poweroff SP")
        report.error( ibmc['ip']+" get fwInfo failed,  make sure you have poweroff SP")
    return rets


if __name__=='__main__':
    pass
