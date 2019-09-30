#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2019, Huawei.
# Author: xueweihong
# Date: 20190635
# This file is 
# part of Ansible
import json
import re
import sys
import time
import commands
import string
import ConfigParser
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from cfgBmc import *
from commonLoger import ansibleGetLoger
LOG_FILE = "/etc/ansible/ansible_ibmc/log/accountManage.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/accountManage.log"
log,report=ansibleGetLoger(LOG_FILE,REPORT_FILE,"accountManage")

def getAccountsId(ibmc,root_uri,username):
    uri = root_uri  + "/AccountService/Accounts"
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10)
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "getAccountsId send command exception" + str(e) + " \n" )
        raise Exception (ibmc['ip']+"getAccountsId send command exception\n "+str(e))
    try:    
        result = r.status_code
        if result == 200:
            if not  "Members" in list(r.json().keys()):
                return None 
        if len(r.json()["Members"])<0:
                return None
        for eachMembers in r.json()[u"Members"]:
            uri="https://"+ibmc['ip'] + eachMembers[ "@odata.id"]
            r = request('GET',resource=uri,headers=headers,data=playload,tmout=10)
            result = r.status_code
            if  result == 200:
                eachjson=r.json()
                if eachjson['UserName'] == username:
                    return eachjson['Id']
            else :             
                ibmc.log.error(ibmc['ip']+ " -- get each id account failed , the respons is: %s \n" %str(r.json()))
                ret['result'] = False
                ret['msg'] = 'get each id account  failed! the error code is ' + result
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "getAccountsId  failed!" + str(e.message) + " \n" )
    return None         

def getAccounts(ibmc,root_uri):
    uri = root_uri  + "/AccountService/Accounts"
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    playload = {}    
    ret = {'result':True,'msg': 'itest'}
    fileName= str(ibmc['ip'])+"_AccountInfo.json" 
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "getAccounts send command exception" + str(e) + " \n" )
        raise Exception (ibmc['ip']+"getAccounts send command exception\n "+str(e))

    try:    
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- Get accounts successful! " )
            ret['result'] = True
            ret['msg'] = "get account successful,users list as follow:  "
            if not  "Members" in list(r.json().keys()):
                return ret
            if len(r.json()["Members"])<0:
                return ret
            listjson=[]    
            for eachMembers in r.json()[u"Members"]:
                uri="https://"+ibmc['ip'] + eachMembers[ "@odata.id"]
                r = request('GET',resource=uri,headers=headers,data=playload,tmout=10)
                result = r.status_code
                if  result == 200:
                    eachjson=r.json()
                    ret["msg"]=ret['msg']+"userid=%s ,userName=%s :: "%(eachjson[u"Id"],eachjson[u"UserName"]) 
                    listjson.append(eachjson)
                else :             
                    ibmc.log.error(ibmc.ip + " -- get each id account  is: %s \n" %str(r.json()))
                    ret['result'] = False
                    ret['msg'] = 'get each id account  failed! the error code is ' + resul
            ret["msg"]=ret['msg']+"; for more detail please refer to "+fileName
            log.info(ibmc['ip'] + " -- " + ret["msg"])
            report.info(ibmc['ip'] + " -- " + ret["msg"])
            
        else:
            log.error(ibmc['ip'] + " -- get account  is: %s \n" %str(r.json()))
            ret['result'] = False
            ret['msg'] = 'get account  failed! the error code is ' + result
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "get account  failed!" + str(e.message) + " \n" )
        ret['result'] = False
        ret['msg'] = 'get account failed! ' + str(e.message)
    
    jsonfile=None
    
    try:
        jsonfile = open ( '/etc/ansible/ansible_ibmc/report/'+fileName,"w")
        if jsonfile is not None  and listjson is not None :
          json.dump(listjson,jsonfile,indent=4) 
    except Exception ,e:
       log.error( str(ibmc["ip"])+"write json exception :"+str(e) )
    finally:
       if jsonfile is not None:
           jsonfile.close()
    return ret        


def deleteAccount(ibmc,root_uri,username):
    ret = {'result':True,'msg': ''}
    accountId = getAccountsId(ibmc,root_uri,username)
    if accountId is None :
        ret = {'result':False,'msg': 'cant found username '}
        log.error(ibmc['ip'] + " -- " + "can not found username ")
        return  ret 

    uri = root_uri  + "/AccountService/Accounts/"+accountId 
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    playload = {}    
    
    try:
        r = request('DELETE',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "deleteAccount send command exception" + str(e) + " \n" )
        raise Exception (ibmc['ip']+"deleteAccount send command exception\n "+str(e))

    try:     
        
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- delete account successful!\n" )
            report.info(ibmc['ip'] + " -- delete account successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.error(ibmc['ip'] + " -- delete account failed, the respons is: %s \n" %str(r.json()))
            report.error(ibmc['ip'] + " --  delete account failed, the respons is: %s \n" %str(r.json()))    
            ret['result'] = False
            ret['msg'] = 'delete account  failed! the error code is :' + str(result)
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "delete account  exception!" + str(e) + " \n" )
        report.error(ibmc['ip'] + " -- " + "delete account  exception!" + str(e) + " \n" )   
        ret['result'] = False
        ret['msg'] = 'delete account exception! ' + str(e)
    finally:
        return ret 

def createAccount(ibmc,root_uri,account,newPassword,RoleId,Id = None):
    uri = root_uri  + "/AccountService/Accounts/"
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    '''  playload ={ "Id":userId, \
                "UserName":userName,\
                "Password":password,\
                "RoleId":role
              }
    '''     
    configDic={}     
    configDic[u"UserName"]  =   account
    configDic[u"Password"]  =   newPassword  
    configDic[u"RoleId"]  =   RoleId
    if not Id is None:
         configDic["Id"] = Id  

    playload = configDic       
    ret = {'result':True,'msg': ''}
    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "createAccount send command exception" + str(e) + " \n" )
        raise Exception (ibmc['ip']+"createAccount send command exception\n "+str(e))
   
    try:  
        result = r.status_code
        log.info(ibmc['ip'] + str(r) )
        if result == 201:
            log.info(ibmc['ip'] + " -- create account successful!\n" )
            report.info(ibmc['ip'] + " -- create account successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.error(ibmc['ip'] + " -- create account failed , the respons  is: %s \n" %str(r.json()))
            report.error(ibmc['ip'] + " -- create account failed , the respons is: %s \n" %str(r.json()))    
            ret['result'] = False
            ret['msg'] = 'create account failed! the error code is ' + str(result)
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "create account  failed!" + str(e) + " \n" )
        report.error(ibmc['ip'] + " -- " + "create account  failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'create account failed! ' + str(e)
        raise Exception (ibmc['ip'] +"createAccount handler respon exception\n "+str(e))
    finally:
        return ret
        
def modifyAccount( ibmc,root_uri,configfile,newPassword ):
    uri = root_uri  + "/AccountService/Accounts/"
    config=None
    try:
        config = open(configfile, 'r')
        configDic = json.load(config)
    except Exception ,e:    
        log.error(ibmc['ip'] + " -- modifyAccount: read config file failed! error info:%s" %str(e))
        raise Exception (ibmc['ip']+"handler modifyAccount configfile exception \n"+str(e)) 
    finally:
        if config is not None :
            config.close() 
    ret = {'result':True,'msg': ''}
    accountId = getAccountsId(ibmc,root_uri,configDic.keys()[0])
    if accountId is None :
        ret = {'result':False,'msg': 'cant found username '}
        log.error(ibmc['ip'] + " -- " + "can not found username ")
        return  ret   
    uri=uri+accountId       
    log.info(ibmc['ip'] + " -- uri" )
    playload = configDic.values()[0]   
    if  newPassword is not None:
        playload["Password"] = newPassword
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    ret = {'result':True,'msg': ''}
    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "modifyAccount send command exception" + str(e) + " \n" )
        raise Exception (ibmc['ip']+"modifyAccount send command exception\n "+str(e))
    try:    
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- modify account successful! respon json is :" + str(r.json()) )
            report.info(ibmc['ip'] + " -- modify account successful! respon json is :" + str(r.json()) )
            ret['result'] = True
            ret['msg'] = 'cmd send successful! respon json is :' + str(r.json()) 
        else:
            log.error(ibmc['ip'] + " -- modify account failed , the respons is: %s \n" %str(r.json()))
            report.error(ibmc['ip'] + " -- modify account failed , the respons is: %s \n" %str(r.json()))
            ret['result'] = False
            ret['msg'] = 'modify account failed! the error code is ' + result
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "modify account  failed!" + str(e.message()) + " \n" )
        report.error(ibmc['ip'] + " -- " + "modify account  failed!" + str(e.message()) + " \n" )    
        ret['result'] = False
        ret['msg'] = 'modify account failed! ' + str(e.message())
    finally:
        return ret  
        
def accountMain(ibmc,root_uri,command,params ): 
    if command.lower() == "getaccount":
        return getAccounts(ibmc,root_uri)
    elif command.lower() == "deleteaccount":
        return deleteAccount(ibmc,root_uri,params["useraccount"])
    elif command.lower() == "modifyaccount":
        return modifyAccount( ibmc,root_uri,params["extraparam"],params["newpassword"] )
    elif command.lower() == "createaccount":
        return createAccount(ibmc,root_uri,params["useraccount"],params["newpassword"],params["roleid"])
    else:
         ret['result'] = False
         ret['msg'] = 'manage account  failed! command error .  %s  is not supported'%command
         log.error(ibmc['ip'] + " -- " + "manage account  failed! command error \n" )                
         return ret  
        
          
            
   
      
        