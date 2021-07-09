#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import os

from ibmc_ansible.utils import set_result
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH


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
            ibmc:   IbmcBaseConnect Object
    Returns:
        'result':True
        'msg': "Account obtained successfully
        users list as follow: userid=2, userName=Administrator"
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
        if result != 200:
            log_msg = 'Failed to get accounts! The error code is: %s' % result
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if "Members" not in list(r.json().keys()):
            set_result(ibmc.log_info, "The account is empty.", True, ret)
            return ret
        if len(r.json()["Members"]) < 0:
            set_result(ibmc.log_info, "The account is empty.", True, ret)
            return ret

        list_json = []
        for each_members in r.json()[u"Members"]:
            uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
            r = ibmc.request('GET', resource=uri,
                             headers=headers, data=payload, tmout=10)
            result = r.status_code
            if result == 200:
                eachjson = r.json()
                list_json.append(eachjson)
            else:
                log_msg = "Failed to get each id account!"
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

    except Exception as e:
        log_msg = "Get accounts exception! The exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    ret = save_file(ibmc, filename, list_json)
    return ret


def save_file(ibmc, filename, list_json):
    """
    Function:
        Save the query result to a file.
    Args:
        ibmc: Class that contains basic information about iBMC
        filename: Name of the file that stores account information.
        list_json: Query result list
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    """
    ret = {'result': True, 'msg': 'itest'}
    oem_info = ibmc.oem_info

    for each_dic in list_json:
        each_dic.pop("@odata.type")
        each_dic.pop("Links")
        each_dic.pop("@odata.id")
        each_dic.pop("@odata.context")
        each_dic.pop("Password")
        each_dic["Oem"][oem_info].pop("SSHPublicKeyHash")
        each_dic["Oem"][oem_info].pop("Actions")
        each_dic["Oem"][oem_info].pop("MutualAuthClientCert")

    write_result(ibmc, filename, list_json)
    log_msg = "Account obtained successfully. For more detail please refer to %s" % filename
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
        log_error = "Failed to get account id! The error info is: %s" % str(e)
        raise Exception(log_error)
    try:
        result = r.status_code
        if result != 200:
            return None
        if "Members" not in list(r.json().keys()):
            return None
        if len(r.json()["Members"]) == 0:
            return None

        for each_members in r.json()[u"Members"]:
            uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
            r = ibmc.request('GET', resource=uri,
                             headers=headers, data=payload, tmout=10)
            result = r.status_code
            if result != 200:
                log_error = "Failed to get each account id! " \
                            "The response json is: %s \n" % str(r.json())
                raise Exception(log_error)

            each_json = r.json()
            if each_json['UserName'] == username:
                return each_json['Id']

    except Exception as e:
        log_error = "Failed to get account id! The exception info is: %s" % str(e)
        raise Exception(log_error)
    return None


def delete_account(ibmc, username):
    """
    Args:
            username            (str):   account name
    Returns:
        "result": True
        "msg": "Account deleted successfully!"
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': True, 'msg': ''}
    try:
        account_id = get_account_id(ibmc, username)
    except Exception as e:
        set_result(ibmc.log_error, str(e), False, ret)
        return ret

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
        log_msg = "Failed to delete account! The exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
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
        "result": True
        "msg": "The account is created successfully!"
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': ''}

    # Check whether the user name exists
    try:
        account_id = get_account_id(ibmc, new_account)
        role_id = format_role_id(ibmc, role_id)
    except Exception as e:
        log_msg = "Failed to create account! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    if account_id is not None:
        log_msg = "Failed to create account! the username: %s exists" % str(new_account)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    uri = "%s/AccountService/Accounts/" % ibmc.root_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {u"UserName": new_account, u"Password": new_password,
               u"RoleId": role_id}
    if id is not None:
        payload["Id"] = id

    try:
        r = ibmc.request('POST', resource=uri,
                         headers=headers, data=payload, tmout=10)
    except Exception as e:
        log_msg = "Failed to create account! The exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

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
    Function:
        Collecting Maintenance Information About All Modules of a Board
    Args:
        ibmc : Class that contains basic information about iBMC
        config_dic : account information to be modified
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2021/2/22 21:13
    """
    uri = "%s/AccountService/Accounts/" % ibmc.root_uri

    ret = {'result': False, 'msg': ''}
    (ord_account, change_message), = config_dic.items()
    if not ord_account:
        log_msg = "iBMC user info can not be found."
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    try:
        account_id = get_account_id(ibmc, ord_account)
    except Exception as e:
        log_msg = "Failed to modify account! The exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if account_id is None:
        log_msg = "The username: %s to be modified cannot be found." % ord_account
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    uri = uri + account_id
    payload = change_message

    Etag = ibmc.get_etag(uri)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token, 'If-Match': Etag}
    ret = {'result': True, 'msg': ''}
    try:
        r = ibmc.request('PATCH', resource=uri, headers=headers, data=payload, tmout=10)
    except Exception as e:
        log_msg = "Failed to modify account, the exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    try:
        result = r.status_code
        if result != 200:
            log_msg = "Failed to modify account, the response info is: %s" % (
                str(r.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if r.json().get("@Message.ExtendedInfo"):
            log_msg = "Partially succeeded in modifying the account, " \
                      "the detailed information is: %s" % str(r.json().get("@Message.ExtendedInfo"))
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Account modified successfully!"
            set_result(ibmc.log_info, log_msg, True, ret)
    except Exception as e:
        log_msg = "Failed to modify account, the exception info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret
