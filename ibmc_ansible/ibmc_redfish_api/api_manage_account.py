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
    format_role_id = rold_id_dic.get(role_id.lower())
    if format_role_id is None:
        raise Exception("The role id: %s is incorrect, please check whether the role id exists in %s" %
                        (str(role_id), str(rold_id_dic.values())))
    return format_role_id


def get_accounts(ibmc):
    """
    Args:
            ibmc            :   IbmcBaseConnect 对象
    Returns:
        {'result':True,'msg': "Account obtained successfully, users list as follow: userid=2 ,userName=Administrator"}
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
        r = ibmc.request('GET', resource=uri, headers=headers,
                         data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("Failed to get accounts! The error info is: %s" % str(e))
        raise Exception("Failed to get accounts! The error info is: %s" % str(e))

    try:
        result = r.status_code
        if result == 200:
            log_msg = "Account obtained successfully, users list as follow:"

            if not "Members" in list(r.json().keys()):
                set_result(ibmc.log_info, log_msg, True, ret)
                return ret
            if len(r.json()["Members"]) < 0:
                set_result(ibmc.log_info, log_msg, True, ret)
                return ret
            list_json = []
            for each_members in r.json()[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri,
                                 headers=headers, data=payload, tmout=10)
                result = r.status_code
                if result == 200:
                    eachjson = r.json()
                    log_msg = "%s userid=%s, username=%s; |" % (
                        log_msg, eachjson[u"Id"], eachjson[u"UserName"])
                    list_json.append(eachjson)
                else:
                    log_msg = "Failed to get each id account! The response json is: %s" % str(
                        r.json())
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret

            log_msg = "%s For more detail please refer to %s" % (
                log_msg, filename)
        else:
            log_msg = 'Failed to get accounts! The error code is: %s' % result
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "Get accounts exception! The exception info is: %s" % str(e)
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
        account id
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
        r = ibmc.request('GET', resource=uri, headers=headers,
                         data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("Failed to get account id! The error info is: %s" % str(e))
        raise Exception("Failed to get account id! The error info is: %s" % str(e))
    try:
        result = r.status_code
        if result == 200:
            if not "Members" in list(r.json().keys()):
                return None
            if len(r.json()["Members"]) < 0:
                return None
            for each_members in r.json()[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri,
                                 headers=headers, data=payload, tmout=10)
                result = r.status_code
                if result == 200:
                    each_json = r.json()
                    if each_json['UserName'] == username:
                        return each_json['Id']
                else:
                    ibmc.log_error(
                        "Failed to get each account id! The response json is: %s \n" % str(r.json()))
                    raise Exception("Failed to get each account id!")

    except Exception as e:
        ibmc.log_error("Failed to get account id! The exception info is: %s" % str(e))
        raise
    return None


def delete_account(ibmc, username):
    """
    Args:
            username            (str):   account name
    Returns:
        {"result": True, "msg": "Account deleted successfully!"}
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
        log_msg = "The username: %s to be deleted cannot be found." % str(username)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    uri = "%s/AccountService/Accounts/%s" % (ibmc.root_uri, account_id)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}

    try:
        r = ibmc.request('DELETE', resource=uri,
                         headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("Failed to delete account! The exception info is: %s" % str(e))
        raise Exception("Failed to delete account! The exception info is: %s" % str(e))
    try:
        result = r.status_code
        if result == 200:
            log_msg = "The iBMC account: %s deleted successfully!" % str(username)
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Failed to delete account! The response json is: %s" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = 'Delete account exception! The exception info is：%s' % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def create_account(ibmc, new_account, new_password, role_id, id=None):
    """
    Args:
            new_account            (str):  user account
            new_password           (str):  new password
            role_id                (str):  roled id
            id                     (str):  user id
    Returns:
        {"result": True, "msg": "The account is created successfully!"}
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
        log_msg = "Failed to create account! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Check whether the user name exists
    account_id = get_account_id(ibmc, new_account)
    if account_id is not None:
        log_msg = "Failed to create account! the username: %s exists" % str(new_account)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    uri = "%s/AccountService/Accounts/" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    payload[u"UserName"] = new_account
    payload[u"Password"] = new_password
    payload[u"RoleId"] = role_id
    if not id is None:
        payload["Id"] = id

    try:
        r = ibmc.request('POST', resource=uri,
                         headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error(
            "Failed to create account! The exception info is: %s" % str(e))
        raise Exception(
            "Failed to create account! The exception info is: %s" % (str(e)))

    try:
        result = r.status_code
        if result == 201:
            log_msg = "The account is created successfully!"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            error_msg = r.json().get("error").get(
                '@Message.ExtendedInfo')[0].get("Message")
            if r.json().get("error").get('@Message.ExtendedInfo')[0].get("Message") is None:
                error_msg = str(r.json())
            log_msg = "Failed to create account! The error message is: %s \n" % error_msg
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "Failed to create account! The error info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def modify_account(ibmc, config_dic):
    """
    Args:
            config_dic            (dic):  iBMC user info
    Returns:
        {'result':True,'msg': 'Account modified successfully!'}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/AccountService/Accounts/" % ibmc.root_uri

    ret = {'result': False, 'msg': ''}
    if len(config_dic) != 1:
        log_msg = "iBMC user info can not be found."
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    account_id = get_account_id(ibmc, str(list(config_dic.keys())[0]))
    if account_id is None:
        log_msg = "The username: %s to be modified cannot be found." % str(list(config_dic.keys())[0])
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
        r = ibmc.request('PATCH', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        ibmc.log_error("Failed to modify account, the exception info is: %s" % str(e))
        raise Exception("Failed to modify account, the exception info is: %s" % str(e))

    try:
        result = r.status_code
        if result == 200:
            if r.json().get("@Message.ExtendedInfo"):
                log_msg = "Partially succeeded in modifying the account, the detailed information is: %s" % str(
                    r.json().get("@Message.ExtendedInfo"))
                set_result(ibmc.log_info, log_msg, True, ret)
            else:
                log_msg = "Account modified successfully!"
                set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Failed to modify account, the response info is: %s" % (
                str(r.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "Failed to modify account, the exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret
