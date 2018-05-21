#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Huawei.
#
# This file is part of Ansible
#

import os
import requests
import json
import re
import sys
import time
from datetime import datetime
import traceback

token = ''
sessionid = ''
Etag = ''
isHTTPS = True


'''
#==========================================================================
# @Method: package get SystemUri method
# @command: send_get_request
# @Param: ibmc url
# @date: 2017.9.16
#==========================================================================
'''
def getSystemUri(ibmc, uri, tmout):
    try:
        response = sendGetRequest(ibmc,uri,tmout)
        if response is None:
            ret = 'HTTP request exception!'
        else:
            try:
                ret = response.json()
                ret = ret['Members'][0]['@odata.id']
            except:
                raise
    except:
        raise

    return ret

'''
#==========================================================================
# @Method: package get request method
# @command: send_get_request
# @Param: ibmc url
# @date: 2017.9.16
#==========================================================================
'''
def sendGetRequest(ibmc, uri, tmout):
    result = {}
    try:
        response = request('GET', uri, data='',tmout=tmout,ip=ibmc['ip'])
    except:
        raise
    return response

'''
#==========================================================================
# @Method: package post request method
# @command: send_post_request
# @Param: ibmc url body headers
# @date: 2017.9.16
#==========================================================================
'''
def sendPostRequest(ibmc, uri, pyld, hdrs):
    result = {}
    try:
        response = request('POST',uri, headers=None, data=json.dumps(pyld), tmout=10,ip=ibmc['ip'])
    except:
        raise
    return response

'''
#==========================================================================
# @Method: package patch request method
# @command: send_patch_request
# @Param: ibmc url body headers
# @date: 2017.9.16
#==========================================================================
'''
def sendPatchRequest(ibmc, uri, pyld, hdrs,tmout):
    result = {}
    try:
        response = requests.patch(uri, data=json.dumps(pyld), headers=hdrs,
                           verify=False, auth=(ibmc['user'], ibmc['pswd']))
    except:
        raise
    return response

'''
#==========================================================================
# @Method: query Etag
# @command: get_etag
# @Param: ibmc url
# @date: 2017.9.18
#==========================================================================
'''
def getEtag(ibmc,uri):
    Etag = ''

    #get Etag
    try:
        response = sendGetRequest(ibmc, uri, 100)
    except:
        raise
    if response is None:
        ret = {'status_code':999,'message':'HTTP request exception!','headers':''}
    elif response.status_code == 200:
        ret = {'status_code':200,'message':response.content,'headers':response.headers}
        if 'ETag' in ret['headers'].keys():
           Etag = ret['headers']['ETag']
        elif 'etag' in ret['headers'].keys():
           Etag = ret['headers']['etag']
            
    else:
        try:
            ret = {'status_code':response.status_code,'message':response.json(),'headers':response.headers}
        except:
            raise
        if 'Etag' in ret['headers'].keys():
            Etag = ret['headers']['ETag']
        if 'etag' in ret['headers'].keys():
            Etag = ret['headers']['etag']
    setEtag(Etag)
    return Etag

'''
#==========================================================================
# @Method: package request method
# @command: request
# @Param: method resource headers body tmout ip
# @date: 2017.9.18
#==========================================================================
'''
def request(method, resource, headers=None, data=None,tmout=10,ip=''):
    if headers == None:
        headers = {'X-Auth-Token': token,
           'content-type': 'application/json',
           'If-Match': Etag}
    if type(data) is dict:
        payload = json.dumps(data)
    else:
        payload = data
    url = resource
    try:
        if method == 'POST':
            r = requests.post(url, data=payload, headers=headers, verify=False, timeout=tmout)
        elif method == 'GET':
            r = requests.get(url, data=payload, headers=headers, verify=False, timeout=tmout)
        elif method == 'DELETE':
            r = requests.delete(url, data=None, headers=headers, verify=False, timeout=tmout)
        elif method == 'PATCH':
            r = requests.patch(url, data=payload, headers=headers, verify=False, timeout=tmout)
        else:
            return None
    except Exception as e:
        raise
    return r
   
'''
#==========================================================================
# @Method: create session
# @command: CreateSession
# @Param: ibmc timeout
# @date: 2017.9.15
#==========================================================================
'''
def createSession(ibmc,timeout):
    token = ''
    sessionid = ''
    url = 'https://'+ibmc['ip'] + '/redfish/v1/SessionService/Sessions'
    payload = {'UserName': ibmc['user'], 'Password': ibmc['pswd']}
    try:
        r = request('POST', url, data=payload,tmout=timeout,ip=ibmc['ip'])
    except:
        raise

    if r is None:
        return False
    elif r.status_code == 201:
        index = r.headers['Location'].find("/redfish")
        if index != -1:
            location = r.headers['Location'][index:]
            sessionid = location.split('/')[5]
        else:
            location = r.headers['Location']
            sessionid = location.split('/')[5]
        token = r.headers['X-Auth-Token']
        setToken(token)
        setSessionid(sessionid)
        return True 
    else:
        return False	

'''
#==========================================================================
# @Method: delete session
# @command: DeleteSession
# @Param: ibmc timeout
# @date: 2017.9.15
#==========================================================================
'''
def deleteSession(ibmc,timeout):
    sessionid = getSessionid()
    url = 'https://'+ibmc['ip'] + '/redfish/v1/SessionService/Sessions/' + sessionid
    playload = {'UserName': ibmc['user'], 'Password': ibmc['pswd']}
    r = request('DELETE',url,data=playload,tmout=timeout,ip=ibmc['ip'])
    if r is None:
        ret = {'status_code':999,
                'message':'HTTP requset exception!!',
                'headers':''}
    elif r.status_code == 200:
        ret = {'status_code':r.status_code,
                'message':r.content,
                'headers':r.headers}
    else:
        try:
            ret = {'status_code':r.status_code,
                    'message':r.json(),
                    'headers':r.headers}
        except:
            ret = {'status_code':r.status_code,
                    'message':r,
                    'headers':r.headers}
    return ret

   
'''
#==========================================================================
# @Method: set token
# @command: 
# @Param: token
# @date: 2017.10.18
#==========================================================================
'''
def setToken(g_token):
    global token
    token = g_token

'''
#==========================================================================
# @Method: get token
# @command: 
# @Param: 
# @date: 2017.10.18
#==========================================================================
'''
def getToken():
    global token
    return token

'''
#==========================================================================
# @Method: set sessionid
# @command: 
# @Param: sessionid
# @date: 2017.10.18
#==========================================================================
'''
def setSessionid(g_sessionid):
    global sessionid
    sessionid = g_sessionid

'''
#==========================================================================
# @Method: get sessionid
# @command: 
# @Param: 
# @date: 2017.10.18
#==========================================================================
'''
def getSessionid():
    global sessionid
    return sessionid

'''
#==========================================================================
# @Method: set global Etag
# @command: 
# @Param: e_tag
# @date: 2017.10.18
#==========================================================================
'''
def setEtag(g_etag):
    global Etag
    Etaf = g_etag

'''
#==========================================================================
# @Method: get global Etag 
# @command: 
# @Param: 
# @date: 2017.10.18
#==========================================================================
'''
def getEtags():
    global Etag
    return Etag
