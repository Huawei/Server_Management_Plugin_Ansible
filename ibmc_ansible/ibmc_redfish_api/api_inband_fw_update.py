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
import time

from ibmc_ansible.ibmc_redfish_api.api_power_manager import manage_power, get_power_status

from ibmc_ansible.utils import IBMC_REPORT_PATH, write_result, set_result

CHECK_INTERVAL = 6
# total time= 6s*20
WAIT_TRANFILE_TIME = 20
# total time= 6s*100
WATT_UPGRADE_RES = 150
# total 900s
WAIT_SPSTART = 9
KEEP_CONNECT_INTERVAL = 100
WAIT_POWEROFF = 120
SP_STATUS_POWEROFF = "OSIsPoweredOff"
SP_STATUS_OPERABLE = "SPIsOperable"
SP_STATUS_WORKING = "SPIsWorking"
WAIT_SP_START_TIME = 300
BMC_EXPECT_VERSION = "3.20"

def sp_api_get_status(ibmc):
    """
    Args:
            arg1            (str):
    Returns:
        spStatus
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = ibmc.manager_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload)
        result = r.status_code

        if result == 200:
            ibmc.log_info("get sp status successfully")
            return r.json()["Oem"]["Huawei"]["SPStatus"]
        else:
            ibmc.log_error("get sp status error; code is: %s" % result)
            return None
    except Exception as e:
        ibmc.log_error("get sp status exception; exception is: %s" % str(e))
        raise


def sp_api_set_sp_service(ibmc, sp_enable, restart_timeout=30, deploy_timeout=7200, deploy_status=True):
    """
    Args:
            sp_enable                 (bool): enable the sp
            restart_timeout           (str): restart time
            deploy_timeout          (str): sp deploy time out
            deploy_status             (bool): sp deploy status
    Returns:
        None
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/SPService" % ibmc.manager_uri
    etag = ibmc.get_etag(uri)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}
    playload = {
        "SPStartEnabled": sp_enable,
        "SysRestartDelaySeconds": restart_timeout,
        "SPTimeout": deploy_timeout,
        "SPFinished": deploy_status
    }
    ret = {'result': True, 'msg': ''}
    try:
        r = ibmc.request('PATCH', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            log_msg = "setSpService successful!%s" % str(r.json())
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "set set SpService error info is: %s \n" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "set set SpService failed! exception:%s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def sp_api_set_fw_upgrade(ibmc, image_url, signal_url, image_type="Firmware", parameter="all", upgrade_mode="Auto",
                          active_method="Restart", upgrade_id="1"):
    """
    Args:
            image_url            (str):
            signal_url            (str):
            image_type            (str):
            parameter             (str):
            upgrade_mode          (str):
            active_method         (str):
            upgrade_id             (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    uri = "%s/SPService/SPFWUpdate/%s/Actions/SPFWUpdate.SimpleUpdate" % (ibmc.manager_uri, upgrade_id)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    playload = {
        "ImageURI": image_url,
        "SignalURI": signal_url,
        "ImageType": image_type,
        "Parameter": parameter,
        "UpgradeMode": upgrade_mode,
        "ActiveMethod": active_method
    }
    ret = {'result': True, 'msg': ''}
    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            ibmc.log_info("sp api set fw upgrade successful!\n")
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log_msg = "set sp_api_set_fw_upgrade error info is: %s \n" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "set FwUpgrade failed! %s " % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def sp_api_get_fw_info(ibmc):
    """
    Args:
            arg1            (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': '', "fwInfo": []}
    uri = "%s/SPService/DeviceInfo" % ibmc.manager_uri
    token = ibmc.get_token()
    headers = {'X-Auth-Token': token}
    playload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            ibmc.log_info("get FwInfo successful!\n")
            ret['result'] = True
            ret['msg'] = 'successful!'
            if r.json().get("PCIeCards"): # PCIeCards is empty or do not has the key PCIeCards should raise 
                ret["fwInfo"] = r.json().get("PCIeCards") 
            else:
                ibmc.log_error("get FWInfo failed! do not has keys PCIeCards or PCIeCards is empty ;"
                               "Maybe you should start sp once")
                raise Exception("get FWInfo failed! do not has keys PCIeCards or PCIeCards is empty;"
                                "Maybe you should start sp once")
        else:
            log_msg = "get FwInfo error info is: %s \n" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("get FWInfo failed! %s" % str(e))
        raise
    return ret


def sp_api_get_fw_update_id(ibmc):
    """
    Args:
            arg1            (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': '', "updateidlist": []}
    uri = "%s/SPService/SPFWUpdate" % ibmc.manager_uri
    token = ibmc.get_token()
    headers = {'X-Auth-Token': token}
    playload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            ibmc.log_info("sp api get fw updateId successful!")
            ret['result'] = True
            ret['msg'] = 'successful!'
            tmpdic = r.json()
            ret["updateidlist"] = range(len(tmpdic["Members"]))
        else:
            log_msg = "set sp api get fw updateId error info is: %s \n" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "sp api get fw updateId failed! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def sp_api_get_fw_source(ibmc, upgrade_id="1"):
    """
    Args:
            updateId            (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': '', "SourceInfo": {}}
    uri = "%s/SPService/SPFWUpdate/%s" % (ibmc.manager_uri, upgrade_id)
    token = ibmc.get_token()
    headers = {'X-Auth-Token': token}
    playload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            ibmc.log_info("sp api get fw source successful!")
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["SourceInfo"].update(r.json())
        else:
            log_msg = "set sp api get fw source error info is: %s " % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "sp api get fw_source failed! exception is :%s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def sp_api_get_result_id(ibmc):
    """
    Args:
            arg1            (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': '', "resultIdlist": []}
    uri = "%s/SPService/SPResult" % ibmc.manager_uri
    token = ibmc.get_token()
    headers = {'X-Auth-Token': token}
    playload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=playload, tmout=10)
        result = r.status_code
        if result == 200:
            ibmc.log_info("sp_api_get_fw_source successful!")
            tmp_dic = r.json()
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["resultIdlist"] = range(len(tmp_dic["Members"]))
        else:
            log_msg = "set sp_api_get_result_id error info is: %s " % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "sp api get result id failed! %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def sp_api_get_result_info(ibmc, result_id="1"):
    """
    Args:
         resultId            (str):
    Returns:
         ret{'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    ret = {'result': False, 'msg': '', "resultInfo": {}}
    uri = "%s/SPService/SPResult/%s" % (ibmc.manager_uri, result_id)
    token = ibmc.get_token()
    headers = {'X-Auth-Token': token}
    playload = {}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=playload, tmout=30)
        result = r.status_code
        if result == 200:
            ibmc.log_info("sp api get result info successful!")
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["resultInfo"].update(r.json())
        else:
            log_msg = "set sp api get result info error info is: %s \n" % str(r.json())
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "sp api get result info failed! %s " % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def get_file_name(url):
    """
    Args:
            arg1            (str):
    Returns:
        str
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    tmplist = url.split("/")
    if tmplist == [] or tmplist is None:
        return ""
    else:
        return tmplist[len(tmplist) - 1]


def sp_upgrade_fw_process(ibmc, file_path_list):
    """
    Args:
            file_path_list            (list):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    # Check the BMC version
    r = ibmc.check_ibmc_version(BMC_EXPECT_VERSION)
    if r is False:
        rets={} 
        log_msg = "ibmc version must be %s or above" % BMC_EXPECT_VERSION
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    rets = {'result': True, 'msg': ''}
    upgrade_id = "1"
    ret = manage_power(ibmc, "PowerOff")
    if ret['result'] is True:
        ibmc.log_info("ForceOff system successfully!")
    else:
        log_msg = "ForceOff  system failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    time.sleep(5)
    for cnt_times in range(WAIT_POWEROFF):
        time.sleep(1)
        ret = get_power_status(ibmc)
        if "off" in ret['msg'].lower():
            break
        if cnt_times == WAIT_POWEROFF - 1:
            ibmc.log_error("power state is still on after 120 s")
    for cnt_times in range(WAIT_POWEROFF):
        time.sleep(1)
        try:
            ret = sp_api_get_status(ibmc)
            if ret is None:
                ibmc.log_error("get sp status return None ")
        except Exception as e:
            ibmc.log_error("get sp status exception exception is :%s" % str(e))
            continue
        if (SP_STATUS_POWEROFF in ret):
            break
        if cnt_times == WAIT_POWEROFF - 1:
            ibmc.log_info("sp state is still on after 120 s")

    ret = sp_api_get_fw_update_id(ibmc)
    try:
        if ret['result'] is True:
            ibmc.log_info("GetFwUpdateId  successfully!")
            if ret["updateidlist"] != [] or ret["updateidlist"] is not None:
                upgrade_id = str(ret["updateidlist"][0] + 1)
            else:
                log_msg = "Get Fw Update Id failed!  updateidlist is none"
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
        else:
            log_msg = "Get Fw Update Id failed! result is not true"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
    except Exception as e:
        ibmc.log_error("parse fw upgrade_id exception :%s" % str(e))
        raise Exception("parse fw_upgrade_id exception :%s" % str(e))

    result_dic = {}
    config_list = file_path_list
    i = -1
    filelist = None
    if config_list != []:
        for each_items in config_list:
            fw_file_uri = each_items
            fw_signal_uri = fw_file_uri + ".asc"

            tmp_filename = get_file_name(each_items)
            result_dic[tmp_filename] = "inited"
            ret = sp_api_set_fw_upgrade(ibmc, fw_file_uri, fw_signal_uri, upgrade_id=upgrade_id)
            if ret['result'] is True:
                ibmc.log_info("set fw upgrade  successfully!")
            else:
                result_dic[tmp_filename] = "failed"
                ibmc.log_error("set fw upgrade failed!")
                ibmc.report_error("upgarde Fw failed! sp_api_set_fw_upgrade failed!")
                continue
            # check files has transfer to bmc
            filename = get_file_name(each_items)
            asc_file = filename + ".asc"
            for i in range(WAIT_TRANFILE_TIME):
                time.sleep(CHECK_INTERVAL)
                ret = sp_api_get_fw_source(ibmc, upgrade_id=upgrade_id)
                if ret['result'] is True:
                    filelist = ret["SourceInfo"]["FileList"]
                    if filelist == [] or filelist is None:
                        continue
                    else:
                        if (filename in filelist) and (asc_file in filelist):
                            ibmc.log_info("get fw source  successfully!")
                            break

            if i == (WAIT_TRANFILE_TIME - 1):
                result_dic[tmp_filename] = "failed"
                if filename not in filelist:
                    ibmc.log_error("transfer file %s  failed  all file list: %s " % (filename, str(filelist)))
                    ibmc.report_error("transfer file %s  failed  all file list: %s " % (filename, str(filelist)))
                if asc_file not in filelist:
                    ibmc.log_error("transfer file %s  failed  all file list: %s please check  if  %s is exist" % (
                        asc_file, str(filelist), asc_file))
                    ibmc.report_error("transfer file %s  failed  all file list: %s please check  if  %s is exist" % (
                        asc_file, str(filelist), asc_file))

    else:
        log_msg = "get config failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    if "inited" not in result_dic.values():
        log_msg = "upgrade Fw failed! set upgrade failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

        # start sp to  upgrade
    ret = sp_api_set_sp_service(ibmc, sp_enable=True)
    if ret['result'] is True:
        ibmc.log_info("set sp_service  successfully!")
    else:
        time.sleep(CHECK_INTERVAL)
        ret = sp_api_set_sp_service(ibmc, sp_enable=True)
        if ret['result'] is True:
            ibmc.log_info("set sp service again successfully!")
        else:
            log_msg = "set sp service again failed!"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
            # power on
    ret = manage_power(ibmc, "PowerOn")
    if ret['result'] is True:
        ibmc.log_info("power on system successfully!")
    else:
        log_msg = "power on  system failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

        # wait sp start and keep connect
        # wait sp start  30 min time out
    for cnt in range(WAIT_SP_START_TIME):
        ret = sp_api_get_status(ibmc)
        if SP_STATUS_WORKING == ret:
            break
        if cnt >= WAIT_SP_START_TIME - 1:
            log_msg = "upgrade failed , wait sp start timeout"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
        time.sleep(CHECK_INTERVAL)

        # check if fw upgrade ok
    for i in range(len(config_list) * WATT_UPGRADE_RES):
        time.sleep(CHECK_INTERVAL)
        try:
            ret = sp_api_get_result_info(ibmc, result_id=upgrade_id)
        except Exception as e:
            ibmc.log_error("get upgrade result exception %s" % str(e))
            continue

        if ret['result'] is True:
            try:
                if "100" in ret["resultInfo"]["Upgrade"]["Progress"]:
                    result_info_list = ret["resultInfo"]["Upgrade"]["Detail"]
                else:
                    ibmc.log_info("upgrade has not finished")
                    continue
                for each_items in config_list:
                    filename = get_file_name(each_items)
                    for each_dic in result_info_list:
                        if filename in each_dic["Firmware"]:
                            result_dic[filename] = each_dic["Status"]
                            if each_dic["Status"] != "upgraded":
                                ibmc.log_error("%s upgrade failed  : %s" % (filename, str(each_dic["Description"])))
                                ibmc.report_error(
                                    "%s upgrade failed  : %s" % (filename, str(each_dic["Description"])))
                            break
            except Exception as e:
                ibmc.log_info("%s parse upgrade result exception" % str(e))
                continue
                # result is ok
            if (not "inited" in result_dic.values()) and (result_dic != {}):
                if "failed" in result_dic.values():
                    log_msg = " upgrade failed %s" % str(result_dic)
                    set_result(ibmc.log_error, log_msg, False, rets)
                else:
                    log_msg = "upgrade successfully %s" % str(result_dic)
                    set_result(ibmc.log_info, log_msg, True, rets)
                return rets
        else:
            ibmc.log_error("sp_api_get_result_info failed! %s" % (ret['msg']))
            continue

    log_msg = "check result timeout "
    set_result(ibmc.log_error, log_msg, False, rets)
    return rets


def get_fw_info(ibmc):
    """
    Args:
            arg1            (str):
    Returns:
        ret{'result':'','msg':''}
    Raises:
        Exception
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    rets = {'result': True, 'msg': ''}
    # Check the BMC version
    r = ibmc.check_ibmc_version(BMC_EXPECT_VERSION)
    if r is False:
        rets={} 
        log_msg = "ibmc version must be %s or above" % BMC_EXPECT_VERSION
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    try:
        ret = sp_api_get_status(ibmc)
        if ret is None:
            log_msg = "get sp status return None "
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
    except Exception as e:
        ibmc.log_error("get sp status exception exception is :%s" % str(e))
        raise
    if not (SP_STATUS_OPERABLE in ret or SP_STATUS_POWEROFF in ret):
        log_msg = "sp service  can access  ,sp status is : %s" % ret
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    ret = sp_api_get_fw_info(ibmc)
    if ret["result"] is True:
        if ret["fwInfo"] == [] or ret["fwInfo"] is None:
            log_msg = "get fwInfo failed "
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
        msg = 'get fw info successfully msg:\n=============================================== \n'
        try:
            for eachFw in ret["fwInfo"]:
                msg = "%sDeviceName:%s \n" % (msg, eachFw["DeviceName"])
                msg = "%sManufacturer:%s \n" % (msg, eachFw["Controllers"][0]["Manufacturer"])
                msg = "%sModel:%s \n" % (msg, eachFw["Controllers"][0]["Model"])
                msg = "%sFirmwareVersion:%s \n" % (msg, eachFw["Controllers"][0]["FirmwareVersion"])
                msg = "%s=============================================== \n" % msg
        except Exception as err:
            ibmc.log_error("parse fw Info exception : %s" % str(err))
        fw_info_dic = {"fwinfo": ret["fwInfo"]}
        filename = os.path.join(IBMC_REPORT_PATH, "inband_fw_info/%s_fwInfo.json" % str(ibmc.ip))
        write_result(ibmc, filename, fw_info_dic)

        log_msg = "%sfor more info please refer to %s" % (msg, filename)
        set_result(ibmc.log_info, log_msg, True, rets)

    else:
        log_msg = "get fwInfo failed"
        set_result(ibmc.log_error, log_msg, False, rets)

    return rets
