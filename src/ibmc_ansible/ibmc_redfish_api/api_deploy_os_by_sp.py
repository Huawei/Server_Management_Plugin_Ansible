#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import time

from ibmc_ansible.ibmc_redfish_api.api_inband_fw_update import sp_api_set_sp_service, sp_api_get_status, \
    SP_STATUS_WORKING, WAIT_SP_START_TIME, CHECK_INTERVAL
from ibmc_ansible.ibmc_redfish_api.api_power_manager import manage_power

from ibmc_ansible.utils import set_result

BMC_EXPECT_VERSION = "3.20"
SP_EXPECT_VERSION = "1.09"


def config_os(ibmc, os_config):
    """
     Function:
         config the os you want to deploy
     Args:
          ibmc (str):   IbmcBaseConnect Object
          os_config   (dict):
     Returns:

     Raises:
         Exception
     Examples:
         None
     Author:
     Date: 10/26/2019
    """
    ret = {'result': True, 'msg': ''}
    content = os_config
    # send restful request
    token = ibmc.get_token()
    # get interface id
    uri = "%s/SPService/SPOSInstallPara" % ibmc.manager_uri
    # get etag for headers
    etag = ibmc.get_etag(uri)
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}
    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=content, tmout=10)
        result = r.status_code
        if result == 201:
            log_msg = "post os config parament successfully"
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            if result == 500 or result == 400:
                log_msg = " post os config parament failed! error json:%s" % str(r.json())
                set_result(ibmc.log_error, log_msg, False, ret)
            else:
                log_msg = " post os config parament failed! error code:%s" % str(result)
                set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("post os config parament failed! %s" % str(e))
        raise
    return ret


def set_sp_finished(ibmc):
    """
     Function:
         set sp finished
     Args:
          ibmc (str):   IbmcBaseConnect Object
     Returns:
        ret {}
     Raises:
         Exception
     Examples:
         None
     Author:
     Date: 10/26/2019
    """
    uri = "%s/SPService" % ibmc.manager_uri
    etag = ibmc.get_etag(uri)
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}
    payload = {"SPFinished": True}

    ret = {'result': True, 'msg': ''}
    try:
        r = ibmc.request('PATCH', resource=uri, headers=headers, data=payload, tmout=10)
        result = r.status_code
        if result == 200:
            log_msg = "set SP result finished successful! response is : %s" % str(r.json())
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "set SP result finished failed! error code is: %s" % str(result)
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        ibmc.log_error("set SP result finished failed! exception is: %s" % str(e))
        raise
    return ret


def vmm_is_connected(ibmc):
    """
     Function:
        check vmm if connected
     Args:
          ibmc (str):   IbmcBaseConnect Object
     Returns:
        ret {}
     Raises:
         Exception
     Examples:
         None
     Author:
     Date: 10/26/2019
    """
    result = ''
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = "%s/VirtualMedia/CD" % ibmc.manager_uri
    payload = {}
    try:
        ret = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        if ret.status_code == 200:
            data = ret.json()
            result = data.get(u'Inserted')
        else:
            ibmc.log_error("get vmm info failed!")
            result = 'unknown'
    except Exception as e:
        ibmc.log_error("check vmm connected exception! exception is:%s" % str(e))
    return result


def un_mount_file(ibmc):
    """
     Function:
         unmount file from virtual cd
     Args:
          ibmc (str):   IbmcBaseConnect Object
     Returns:
        ret {}
     Raises:
         Exception
     Examples:
         None
     Author:
     Date: 10/26/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = "%s/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl" % ibmc.manager_uri
    payload = {'VmmControlType': 'Disconnect'}
    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 202:
            ibmc.log_info('unmount successful')
            time.sleep(10)
        elif result == 404:
            ibmc.log_info('unmount Failure:resource was not found')
        elif result == 400:
            ibmc.log.info("unmount Failure:operation failed")
        elif result == 401:
            ibmc.log_info("unmount Failure:session id is timeout or username and password is not correct!")
        else:
            ibmc.log_info('unmount Failure:unknown error ,error code is :%s' % result)
    except Exception as e:
        raise Exception("un mount file exception is :%s" % str(e))
    return result


def mount_file(ibmc, os_img):
    """
     Function:
         mount file to virtual cd
     Args:
          ibmc (str):   IbmcBaseConnect Object
     Returns:
        ret {}
     Raises:
         Exception
     Examples:
         None
     Author:
     Date: 10/26/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    uri = "%s/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl" % ibmc.manager_uri
    payload = {'VmmControlType': 'Connect', 'Image': os_img}
    try:
        r = ibmc.request('POST', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 202:
            ibmc.log_info('mount %s successful ' % os_img.split("/")[-1])
            time.sleep(10)
        elif result == 404:
            ibmc.log_info("mount Failure:resource was not found")
        elif result == 400:
            ibmc.log_info("mount Failure:operation failed")
        elif result == 401:
            ibmc.log_info("mount Failure:session id is timeout or username and password is not correct!")
        else:
            ibmc.log_info("mount Failure:unknown error")
    except Exception as e:
        ibmc.log_error("mount file exception ! exception is:%s" % str(e))
        raise
    return result


def check_deploy_os_result(ibmc):
    """
    Function:
       check deploy os result
    Args:
        ibmc (str):   IbmcBaseConnect Object
    Returns:
      ret {}
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 10/26/2019
    """
    uri = "%s/SPService/SPResult/1" % ibmc.manager_uri
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    rets = {'sp_status': 'Init', 'os_progress': '', 'os_status': '', 'os_step': '', 'os_error_info': ''}
    try:
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=100)
        code = r.status_code
        if code == 200:
            r = r.json()
            sp_status = r[u'Status']
            rets['sp_status'] = sp_status
            ibmc.log_info("SP Status is %s" % sp_status)
            if sp_status == "Deploying" or sp_status == "Running" or sp_status == "Finished":
                rets['os_progress'] = r[u'OSInstall'][u'Progress']
                rets['os_status'] = r[u'OSInstall'][u'Results'][0][u'Status']
                rets['os_step'] = r[u'OSInstall'][u'Results'][0][u'Step']
                rets['os_error_info'] = r[u'OSInstall'][u'Results'][0][u'ErrorInfo']
        else:
            ibmc.log_error("get the sp result failed! error code is %s" % code)
    except Exception as e:
        ibmc.log_error("exception is thrown, get the sp result failed!%s" % str(e))
        rets = {'sp_status': 'Init', 'os_progress': '', 'os_status': '', 'os_step': '', 'os_error_info': ''}

    return rets


def deploy_os_by_sp_process(ibmc, os_img, os_config):
    """
    Function:
       deploy os by sp
    Args:
        ibmc (str):   IbmcBaseConnect Object
        os_img (str):os image path
        os_config(dict):os config dict
    Returns:
      ret {}
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 10/26/2019
    """
    # Check the BMC version
    r = ibmc.check_ibmc_version(BMC_EXPECT_VERSION)
    if r is False:
        rets={} 
        log_msg = "ibmc version must be %s or above" % BMC_EXPECT_VERSION
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

        # Check the SP version
    r = ibmc.check_sp_version(SP_EXPECT_VERSION)
    if r is False:
        rets={} 
        log_msg = "sp version must be %s or above" % SP_EXPECT_VERSION
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

        # get vmm is connected
    rets = vmm_is_connected(ibmc)
    ibmc.log_info("vmm connect stat is :" + str(rets))
    # if is connected,disconnect first
    if rets is True:
        ibmc.log_info("vmm is connected before,unmount ! ")
        un_mount_file(ibmc)
        time.sleep(CHECK_INTERVAL)

    # Power off the X86 system to make sure the SP is not running
    rets = manage_power(ibmc, "PowerOff")
    if rets['result'] is True:
        ibmc.log_info("Power off x86 System successfully!")
    else:
        log_msg = "Power off x86 System failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    time.sleep(10)

    # Set SP Finished, in order to avoid the impact of last result
    rets = set_sp_finished(ibmc)
    if rets['result'] is False:
        log_msg = "set sp result finished failed!please try it again! "
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    # parse ini file and get image config file
    rets = config_os(ibmc, os_config)
    if rets['result'] is False:
        manage_power(ibmc, "PowerOff")
        time.sleep(15)
        rets = config_os(ibmc, os_config)
        if rets['result'] is False:
            return rets

    # Set SP enabled
    rets = sp_api_set_sp_service(ibmc, sp_enable=True)
    if rets['result'] is True:
        ibmc.log_info("set sp_service  successfully!")
    else:
        time.sleep(CHECK_INTERVAL)
        rets = sp_api_set_sp_service(ibmc, sp_enable=True)
        if rets['result'] is True:
            ibmc.log_info("set sp service again successfully!")
        else:
            log_msg = "set sp service again failed!"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets

    # mount OS iso image
    rets = mount_file(ibmc, os_img)
    if rets != 202:
        un_mount_file(ibmc)
        log_msg = "install OS failed! please check the OS image is exist or not!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    # Start the X86 system to make the os config task avaliable and install the OS.
    rets = manage_power(ibmc, "PowerOn")
    if rets['result'] is True:
        ibmc.log_info("power on the X86 system successfully!")
    else:
        un_mount_file(ibmc)
        log_msg = "install os failed! power on x86 System failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    # wait sp start  30 min time out
    for cnt in range(WAIT_SP_START_TIME):
        ret = sp_api_get_status(ibmc)
        if SP_STATUS_WORKING == ret:
            break
        if cnt >= WAIT_SP_START_TIME - 1:
            un_mount_file(ibmc)
            log_msg = "deploy failed , wait sp start timeout"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
        time.sleep(CHECK_INTERVAL)
    # check the OS install result-
    try:
        loopInstall = 0
        while 1:
            loopInstall += 1
            status = check_deploy_os_result(ibmc)
            sp_status = status[u'sp_status']
            os_status = status[u'os_status']
            os_progress = status[u'os_progress']
            os_step = status[u'os_step']
            os_error_info = status[u'os_error_info']
            ibmc.log_info(
                "loopInstall: %s sp_status:%s, os_progress:%s, os_status:%s, os_step:%s, os_error_info:%s \n" % (
                    loopInstall, sp_status, os_progress, os_status, os_step, os_error_info))
            if sp_status == "Init":
                ibmc.log_info("SP is initial, please wait!")
                time.sleep(60)
            elif sp_status == "Finished" and os_status == "Successful" and os_progress == "100":
                log_msg = "os install successfully"
                set_result(ibmc.log_info, log_msg, True, rets)
                return rets
            elif sp_status == "Timeout" or sp_status == "Idle" or os_status == "Failed":
                log_msg = "os install failed ,Error info is: %s" % os_error_info
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
            else:
                time.sleep(60)
            if loopInstall >= 60:
                log_msg = "too many times loop, install OS has time out,please try it again!"
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
    except Exception as e:
        log_msg = "install OS failed! exception error info:%s" % str(e)
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    finally:
        un_mount_file(ibmc)
