#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os

from ibmc_ansible.utils import IBMC_REPORT_PATH, write_result, set_result


def format_role_id(ibmc, role_id):
    """
    Args:
            ibmc            (class):   IbmcBaseConnect 
            role_id          (str):    role id 
    Returns:
        role id
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """

    rold_id_dic = {
        "administrator": "Administrator",
        "operator": "Operator",
        "commonuser": "Commonuser",
        "noaccess": "Noaccess",
        "customrole1": "CustomRole1",
        "customrole2": "CustomRole2",
        "customrole3": "CustomRole3",
        "customrole4": "CustomRole4"
    }
    role_id = rold_id_dic.get(role_id.lower())
    if role_id is None:
        raise Exception("format role id faile, please check role id if in %s" % str(
            rold_id_dic.values()))
    return role_id


def get_accounts(ibmc):
    """
    Args:
            ibmc            (str):   IbmcBaseConnect 对象
    Returns:
        {'result':True,'msg': "accounts info"}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/AccountService/Accounts" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    ret = {'result': True, 'msg': 'itest'}
    filename = os.path.join(
        IBMC_REPORT_PATH, "account_info/%s_AccountInfo.json" % str(ibmc.ip))

    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("getAccounts send command exception %s" % str(e))
        raise Exception("getAccounts send command exception exception is: %s" % str(e))

    try:
        result = r.status_code
        if result == 200:
            ibmc.log_info("Get accounts successful!")

            log_msg = "get account successful,users list as follow:  "

            if not "Members" in list(r.json().keys()):
                set_result(ibmc.log_info, log_msg, True, ret)
                return ret
            if len(r.json()["Members"]) < 0:
                set_result(ibmc.log_info, log_msg, True, ret)
                return ret
            list_json = []
            for each_members in r.json()[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=10)
                result = r.status_code
                if result == 200:
                    eachjson = r.json()
                    log_msg = "%s userid=%s ,userName=%s :: " % (log_msg, eachjson[u"Id"], eachjson[u"UserName"])
                    list_json.append(eachjson)
                else:
                    log_msg = "get each id account  failed  respon json is: %s \n" % str(r.json())
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret

            log_msg = "%s for more detail please refer to %s" % (log_msg, filename)
        else:
            log_msg = 'get account  failed! the error code is %s' % result
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "get account  exception! exception is:%s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    for each_dic in list_json:
        each_dic.pop("@odata.type")
        each_dic.pop("Links")
        each_dic.pop("@odata.id")
        each_dic.pop("@odata.context")
        each_dic.pop("Password")
        each_dic["Oem"]["Huawei"].pop("SSHPublicKeyHash")
        each_dic["Oem"]["Huawei"].pop("Actions")
        each_dic["Oem"]["Huawei"].pop("MutualAuthClientCert")

    write_result(ibmc, filename, list_json)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def get_account_id(ibmc, username):
    """
    Args:
            username            (str):   account name  
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/AccountService/Accounts" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("get_account_id send command exception" % str(e))
        raise Exception("get_account_id send command exception" % str(e))
    try:
        result = r.status_code
        if result == 200:
            if not "Members" in list(r.json().keys()):
                return None
            if len(r.json()["Members"]) < 0:
                return None
            for each_members in r.json()[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=10)
                result = r.status_code
                if result == 200:
                    each_json = r.json()
                    if each_json['UserName'] == username:
                        return each_json['Id']
                else:
                    ibmc.log_error(
                        "get each id account failed; respone json is: %s \n" % str(r.json()))
                    raise Exception("get each id account exception ")

    except Exception as e:
        ibmc.log_error("get_account_id failed! exception is :%s " % str(e))
        raise
    return None


def delete_account(ibmc, username):
    """
    Args:
            username            (str):   account name
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': True, 'msg': ''}
    account_id = get_account_id(ibmc, username)
    if account_id is None:
        ret = {'result': False, 'msg': 'can not find username '}
        ibmc.log_error("can not find username ")
        return ret

    uri = "%s/AccountService/Accounts/%s" % (ibmc.root_uri, account_id)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}

    try:
        r = ibmc.request('DELETE', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("delete_account send command exception %s" % str(e))
        raise Exception("delete_account send command exception %s" % str(e))
    try:
        result = r.status_code
        if result == 200:
            log_msg = "delete account successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "delete account faile ;respon json is: %s " % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = 'delete account exception; exception is：%s' % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def create_account(ibmc, account, new_password, role_id, id=None):
    """
    Args:
            account            (str):  user account 
            new_password       (str):  new password
            role_id             (str):  roled id 
            id                 (str):  
    Returns:
        {'result':True,'msg': ''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': ''}
    try:
        role_id = format_role_id(ibmc, role_id)
    except Exception as e:
        log_msg = "create account  failed! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret 
    uri = "%s/AccountService/Accounts/" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    payload[u"UserName"] = account
    payload[u"Password"] = new_password
    payload[u"RoleId"] = role_id
    if not id is None:
        payload["Id"] = id

    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error(" create_account send command exception; exception is %s" % str(e))
        raise Exception("create_account send command exception; exception is:%s" % (str(e)))

    try:
        result = r.status_code
        if result == 201:
            log_msg = "create account successful!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            error_msg = r.json().get("error").get('@Message.ExtendedInfo')[0].get("Message")
            if r.json().get("error").get('@Message.ExtendedInfo')[0].get("Message") is None:
                error_msg = str(r.json())
            log_msg = "create account failed ! error message is: %s \n" % error_msg
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "create account  failed! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)    
    return ret


def modify_account(ibmc, config_dic):
    """
    Args:
            config_dic            (dic)    
    Returns:
        {'result':True,'msg': ''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/AccountService/Accounts/" % ibmc.root_uri

    ret = {'result': False, 'msg': ''}
    account_id = get_account_id(ibmc, config_dic.keys()[0])
    if account_id is None:
        log_msg = "can not find username"
        set_result(ibmc.log_error, log_msg, False, ret)    
        return ret
    uri = uri + account_id
    payload = config_dic.values()[0]

    Etag = ibmc.get_etag(uri)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token, 'If-Match': Etag}
    ret = {'result': True, 'msg': ''}
    try:
        r = ibmc.request('PATCH', resource=uri,
                         headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("modify_account send command exception :%s" % str(e))
        raise Exception("modify_account send command exception %s " % str(e))

    try:
        result = r.status_code
        if result == 200:
            log_msg = "modify account successful! return json is: %s" % (
                str(r.json()))
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "modify account failed! return json is: %s" % (
                str(r.json()))
            set_result(ibmc.log_Error, log_msg, False, ret)
    except Exception as e:
        log_msg = "modify account  failed! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret
