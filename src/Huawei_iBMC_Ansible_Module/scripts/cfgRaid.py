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
import subprocess
import string
import ConfigParser
import logging, logging.handlers
from datetime import datetime


sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from cfgBmc import *
from powerManage import *

global token
from commonLoger import *
LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgRaidLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgRaidReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"cfgRaidReport")


'''
#==========================================================================
# @Method: get Task Status 
# @command: 
# @Param: 
# @date: 2017.11.01
#==========================================================================
'''
def getTaskStatus(ibmc, taskId, root_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = "https://" + ibmc['ip'] + taskId
    result = []

    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            taskStatus = r[u'TaskState']
            if taskStatus == "Running":
                result.append("Running")
            elif taskStatus == "Completed" and r['Messages']['Message'].find("successfully") != -1 :
                result.append("Successful")
                result.append(r['Messages']['MessageArgs'][0])
                log.info(ibmc['ip'] + " -- taskStatus:%s" %taskStatus)
            else:
                result.append(taskStatus)
                result.append(r['Messages']['Message'])
        else:
            result.append("failed")
            result.append("Unknown error!")
            
    except Exception,e:
        log.exception(ibmc['ip'] + " -- get task status failed! error info:%s" %str(e))
        result = "Exception!"
        result.append(str(e))
        raise

    log.info(ibmc['ip'] + " -- get Task status:%s" %str(result))
    return result

'''
#==========================================================================
# @Method: create logic device 
# @command: 
# @Param: 
# @date: 2017.10.31
#==========================================================================
'''
def creatLD(ibmc, playload, root_uri, system_uri,LDId):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + system_uri + "/Storages/%s"%LDId
    payload = playload 
    try:
        r = request('POST',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])

    except Exception, e:
        log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
        raise

    return r
  
  
'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def deleteLD(ibmc,root_uri, vol_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = "https://" + ibmc['ip'] + vol_uri
    playload = None
    try:
        r = request('DELETE',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])

    except Exception, e:
        log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
        raise

    return r
'''
#==========================================================================
# @Method: get all storgeInfo
# @command: 
# @Param:  ibmc url
# @date: 2018.4.23
#==========================================================================
'''
def getAllStorge(ibmc, root_uri,system_uri):
    raidInfo_uri = system_uri + "/Storages"
    token = getToken()
    result = [] 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + raidInfo_uri
    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            result = r['Members']
    except Exception,e:
        log.error(ibmc['ip'] + " -- get raid info failed!error info:%s " %str(e))
        raise
    return result 
    

'''
#==========================================================================
# @Method: delete a Ld
# @command: 
# @Param:  ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def deletALD(LDID,ibmc,root_uri,system_uri):
    rets = {'result':True,'msg': ''}
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri+system_uri + "/Storages/%s/Volumes/%s"%(LDID.split("/")[0],LDID.split("/")[1])
    try :
        r = request('DELETE',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 202:
            temdic=r.json()
            taskId = temdic[u'@odata.id']  
            log.info("%s %s send delete LD command success"%( str(ibmc["ip"]),LDID ))
        else :
            rets["result"] = False
            rets["msg"]= rets["msg"]+"%s del  %s   failed  "%(str(ibmc["ip"]),LDID)
            log.info("%s %s  delete LD failed"%( str(ibmc["ip"]),LDID ) +"errorInfo:"+str(r.json()) )
            report.info("%s %s  delete LD failed"%( str(ibmc["ip"]),LDID ))
            return rets 
    except Exception, e:
        rets["result"] = False
        rets["msg"]= rets["msg"]+"%s del  %s   failed exception "%(str(ibmc["ip"]),LDID)
        log.error(ibmc['ip'] + " -- deletALd  error:%s" %str(e))
        return rets 
    for i in range(20):
        taskResult = getTaskStatus(ibmc, taskId, root_uri)
        if taskResult[0].find("Running") != -1:
            time.sleep(1)
            continue
        elif taskResult[0].find("Successful") != -1:
            rets["result"] = True
            rets["msg"]= rets["msg"]+"%s del  %s  sucessful  "%(str(ibmc["ip"]),LDID)
            log.info(ibmc['ip'] + " -- the %s delete successful!" %str(LDID))
            report.info(ibmc['ip'] + " -- the %s delete successful!" %str(LDID))
            time.sleep(20)
            break 
        else:
            rets["result"] = False
            rets["msg"]= rets["msg"]+"%s del  %s   failed  "%(str(ibmc["ip"]),LDID)
            log.error(ibmc['ip'] + " -- delete %s failed:%s" %(LDID,taskResult[1]))
            report.error(ibmc['ip'] + " -- delete %s failed:%s" %(LDID,taskResult[1]))
            break
    return rets
'''
#==========================================================================
# @Method: delete all Ld
# @command: 
# @Param:  ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def deletAllLd(storgeId,ibmc, root_uri, system_uri):
    rets = {'result':True,'msg': ''}
    #del all Ld in all storges 
    if  storgeId =="ALL":
        storgelist = getAllStorge(ibmc, root_uri,system_uri)
        if storgelist != [] and storgelist is not None:
            resultList=[]
            for eachinfo in storgelist:
                if not "RAIDStorage" in eachinfo["@odata.id"]:
                    continue
                ret=deletAllLd(eachinfo["@odata.id"].split("/")[6],ibmc, root_uri, system_uri)
                resultList.append(ret)
        if resultList==[]:
           rets["result"]=True
           rets['msg']= ibmc['ip']+" no storage" 
           report.info(ibmc['ip']+ " no storage" )            
           return rets
        for eachResult in  resultList:
            if eachResult["result"] == False:
                rets["result"] = False
            rets["msg"]= rets["msg"] + eachResult['msg']+'\n'
            report.info(ibmc['ip']+ "del storage result:" + rets["msg"] )
        return rets            
    #del all Ld in the assigned storgeId 
    else:
        members = getAllLD(storgeId,ibmc, root_uri, system_uri)
        log.info(ibmc['ip'] + " -- delete Ld:%s" %str(members))
        if len(members) > 0: 
            try:
                rets["result"] =True
                rets["msg"] =''
                for member in members:
                    ret = deleteLD(ibmc, root_uri, member[u'@odata.id'])
                    log.info(ibmc['ip'] + " -- delete ld:%s" %member[u'@odata.id'])
                    ret = ret.json()
                    if ret is not None:
                        taskId = ret[u'@odata.id']
                        status = ret[u'TaskState']
                        for i in range(20):
                            taskResult = getTaskStatus(ibmc, taskId, root_uri)
                            if taskResult[0].find("Running") != -1:
                                time.sleep(1)
                                continue
                            elif taskResult[0].find("Successful") != -1:
                                rets["msg"]= rets["msg"]+"%s del  %s   successful  "%(str(ibmc["ip"]), member[u'@odata.id'] )+"\n"
                                log.info(ibmc['ip'] + " -- the %s delete successful!" %str(member[u'@odata.id']))
                                report.info(ibmc['ip']+ "del storage result:" + rets["msg"] )
                                time.sleep(20)
                                break 
                            else:
                                rets["result"] = False
                                rets["msg"]= rets["msg"]+"%s del  %s   failed  "%(str(ibmc["ip"]), member[u'@odata.id'] )+"\n"
                                log.error(ibmc['ip'] + " -- delete %s failed:%s" %(str(member[u'@odata.id']),taskResult[1]))
                                report.error(ibmc['ip'] + " -- delete %s failed:%s" %(str(member[u'@odata.id']),taskResult[1]))
                                break
                    else:
                        rets["result"] = False
                        rets["msg"]="%s del  %s   failed  "%(str(ibmc["ip"]), member[u'@odata.id'] )
                        log.error("delete all logic disk failed:%s" %taskResult[1])
                        report.error("delete all logic disk failed:%s" %taskResult[1])
                        return rets
                log.info(ibmc['ip'] + " -- all of logic device has be delete! \n")
            except Exception,e:
                rets["result"] = False
                log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
        else:
            rets["result"] = True
            rets["msg"] = ibmc['ip']+"%s there are no logic device create before!"%(storgeId)
            log.info(ibmc['ip'] + " %s -- there are no logic device create before!"%(storgeId))
            report.info(ibmc['ip'] + " %s -- there are no logic device create before!"%(storgeId))
            return rets
        return rets    



'''
#==========================================================================
# @Method: get ld
# @command: 
# @Param: ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def getAllLD(storgeId,ibmc, root_uri, system_uri):
    raidInfo_uri = system_uri + "/Storages/%s/Volumes"%storgeId
    token = getToken()
    result = [] 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + raidInfo_uri
    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            result = r['Members']

    except Exception,e:
        log.error(ibmc['ip'] + " -- get raid info failed!error info:%s " %str(e))
        raise

    return result    

'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def setBootEnable(ibmc, ld):
    uri = "https://" + ibmc['ip'] + str(ld)
    token = getToken()
    eTag = getEtag(ibmc,uri)
    result = True

    headers = {'content-type': 'application/json','X-Auth-Token':token, 'If-Match': eTag}
    payload = {"Oem":{"Huawei":{"BootEnable":True}}}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            log.info(ibmc['ip'] + " -- set boot enable successful!")
            result = r[u'Oem'][u'Huawei'][u'BootEnable']
            
        elif r.status_code == 412:
            log.error(ibmc['ip'] + " -- set boot enable failed, percondition is fault,maybe th etag is error!")
            result = False
        else:
            log.error(ibmc['ip'] + " -- set boot enable failed,unknown reason,error info:" + str(r.status_code))
            result = False

    except Exception,e:
        log.exception(ibmc['ip'] + " -- set boot enable failed! " + str(e))
        result = False 
        raise

    return result


'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param:  ibmc root_uri, system_uri, LDID,playload
# @date: 2017.10.31
#==========================================================================
'''
def modifyARaid(ibmc, root_uri, system_uri, LDID,playload):
    ret = {'result':True,'msg': ''}
    uri = root_uri + system_uri + "/Storages"+"/%s"%LDID
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])
    if r.status_code == 200:
        ret["result"] = True
        ret["msg"] = uri+"modifyARaid successlly"
        return ret 
    else:
        ret["result"] = False
        ret["msg"] = uri + "modifyARaid failed"
        log.error( str(ibmc['ip']) + ret["msg"] + " error msg:"+str(r.json()) )
        return ret
'''
#==========================================================================
# @Method: config raid by configfile
# @command: 
# @Param: configfile ibmc  root_uri, system_uri
# @date: 2017.10.31
#==========================================================================
'''
def modifyRaid( configfile ,ibmc, root_uri, system_uri):
    ret = {'result':True,'msg': ''}
    #before config raid, make sure x86 is power on state!
    powerState = managePower('PowerState', ibmc, root_uri, system_uri)
    log.info(ibmc['ip'] + " -- power state:%s" %str(powerState))
    if powerState.find("On") == -1:
        log.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        report.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        ret['result'] = False
        ret['msg'] = "the system is poweroff, make sure the system is power on , wait 5 mins and try it again!"
        return ret

    config=None
    try:
        config = open(configfile, 'r')
        configDic = json.load(config)
    except Exception ,e:    
        log.error(ibmc['ip'] + " -- read config file failed! error info:%s" %str(e))
        report.info(ibmc['ip'] + " --read config file failed! error info:%s" %str(e))
        raise
    finally:
        if  config is not None :
            config.close()             
    resultList=[]

    for eachConfig in configDic["ldlist"] :
        
        if eachConfig == {} or eachConfig ==None :
            continue 
        try :
            ldid= eachConfig["LDID"]
            playload= eachConfig["LDConfig"]
            tmpDic = { ldid : "failed"}
        except Exception,e:
            log.error(ibmc['ip'] + " -- pares config file failed! error info:%s" %str(e))
            report.info(ibmc['ip'] + " --pares config file failed! error info:%s" %str(e))
            tmpDic[ eachConfig["LDID"] ] = "failed"  
            resultList.append(tmpdic)     

        r= modifyARaid(ibmc, root_uri, system_uri, ldid,playload)
        if r["result"] == True:
            tmpDic[ldid]="success"
            resultList.append(tmpDic)
            time.sleep(20)
        else:
            tmpDic[ldid]="failed"
            resultList.append(tmpDic) 
            log.error( str(ibmc["ip"]) + " modify raid config error Ldid: "+ str(ldid))
    #pares finally result
    for eachResult in resultList:
        if "failed" in eachResult.values():
            ret['result'] = False
            ret['msg'] =str(ibmc["ip"]) +" modify raid failed ,result :"+str(resultList)
            log.error(str(ibmc["ip"]) +" modify raid failed ,result :"+str(resultList))
            report.error(str(ibmc["ip"]) +" modify raid failed ,result :"+str(resultList))
            return ret
    ret['result'] = True
    ret['msg'] = str(ibmc["ip"]) + " modify raid successlly ,result :"+str(resultList)
    log.info(str(ibmc["ip"]) + " modify raid successlly ,result :"+str(resultList))
    report.info( str(ibmc["ip"]) + " modify raid successlly ,result :"+str(resultList))
    return  ret 

'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def cfgRaid(configfile, ibmc, root_uri, system_uri):
    ret = {'result':True,'msg': ''}
    #before config raid, make sure x86 is power on state!
    powerState = managePower('PowerState', ibmc, root_uri, system_uri)
    log.info(ibmc['ip'] + " -- power state:%s" %str(powerState))
    if powerState.find("On") == -1:
        log.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        report.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        ret['result'] = False
        ret['msg'] = "the system is poweroff, make sure the system is power on , wait 5 mins and try it again!"
        return ret

    #parse ini file and get image config file
    config=None 
    try:
        config = open(configfile, 'r')
        configDic = json.load(config)
    except Exception ,e:    
        log.error(ibmc['ip'] + " -- read config file failed! error info:%s" %str(e))
        report.info(ibmc['ip'] + " --read config file failed! error info:%s" %str(e))
        raise
    finally:
        if  config is not None :
            config.close()    
    resultList=[]

    for eachConfig in configDic["LDlist"] :
        if eachConfig =={} or eachConfig is None:
            continue
        tmpdic={eachConfig["RAIDID"]:"failed"}    
        try :    
            LdId=  eachConfig["RAIDID"]  
            if LdId.split("/")[0] =='':
                storgeId=LdId.split("/")[1]
            else:
                storgeId=LdId.split("/")[0]
            playloadDict= eachConfig["configDic"]  
            
        except Exception,e:
            log.error(ibmc['ip'] + " -- pares config file failed! error info:%s" %str(e))
            report.info(ibmc['ip'] + " --pares config file failed! error info:%s" %str(e))
            tmpdic[ eachConfig["RAIDID"] ] = "failed"  
            resultList.append(tmpdic)

    
        taskId = ''
        status = ''
        try:
            #sleep 20s
            loopCreate1 = 0
            loopCreate2 = 0
            loopBootEnable = 0
            time.sleep(20)
            log.info("playload:%s , uri:%s" %(str(playloadDict),root_uri + system_uri))
            r = creatLD(ibmc, playloadDict, root_uri, system_uri,LdId)
            if r.status_code == 202:
                getResultTimes=0               
                result = r.json()
                taskId = result[u'@odata.id']
                status = result[u'TaskState']
                while 1:
                    if getResultTimes >60 :
                         break
                    log.info("taskId:%s" %(str(taskId)))
                    taskResult = getTaskStatus(ibmc, taskId, root_uri)
                    getResultTimes =getResultTimes + 1
                    if taskResult[0].find("Running") != -1:
                        time.sleep(1)
                        continue
                    elif taskResult[0].find("Successful") != -1:
                        tmpdic[ eachConfig["RAIDID"] ] = "success"  
                        resultList.append(tmpdic)
                        log.info(ibmc['ip'] + " -- create %s successful! \n" %eachConfig["RAIDID"])
                        break      
                    else:
                        if loopCreate2 <= 10:
                            time.sleep(20)
                            log.info("playload:%s , uri:%s" %(str(playloadDict),root_uri + system_uri))
                            result = creatLD(ibmc, playloadDict, root_uri, system_uri,LdId)
                            getResultTimes=0
                            result = result.json()
                            taskId = result[u'@odata.id']
                            loopCreate2 += 1
                            log.info(ibmc['ip'] + " -- loopCreate2:%d" %loopCreate2)
                        else: 
                            log.error(ibmc['ip'] + " -- create %s failed! %s" %(eachConfig["RAIDID"],taskResult[1]))
                            tmpdic[ eachConfig["RAIDID"] ] = "failed"  
                            resultList.append(tmpdic)
                            break        
            else:
                log.error(ibmc['ip'] + " -- create  %s failed! error info:%s" %(eachConfig["RAIDID"], str(r.json())))
                tmpdic[ eachConfig["RAIDID"] ] = "failed"  
                resultList.append(tmpdic) 
                continue
        except Exception,e:
            log.error(ibmc['ip'] + " -- create logic device failed! error info:%s" %str(e))
            tmpdic[ eachConfig["RAIDID"] ] = "failed"  
            resultList.append(tmpdic) 
    #pares finally result
    for eachResult in resultList:
        if "failed" in eachResult.values():
            ret['result'] = False
            ret['msg'] =ibmc['ip'] +" cfgRaid failed ,result :"+str(resultList)
            log.error(ibmc['ip'] +" cfgRaid failed ,result :"+str(resultList))
            report.error(ibmc['ip'] +" cfgRaid failed ,result :"+str(resultList))
            return ret
    ret['result'] = True
    ret['msg'] =ibmc['ip'] +" cfgRaid successlly ,result :"+str(resultList)
    log.info(ibmc['ip'] +" cfgRaid successlly ,result :"+str(resultList))
    report.info(ibmc['ip'] +" cfgRaid successlly ,result :"+str(resultList))
    return  ret        
            
'''
#==========================================================================
# @Method: config Main
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def cfgRaidMain(filepath, ibmc, root_uri, system_uri):
    pass 

if __name__ == '__main__':
    main()
 
