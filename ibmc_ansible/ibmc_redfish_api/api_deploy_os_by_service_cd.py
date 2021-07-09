#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

import base64
import re
import time
from ibmc_ansible.ibmc_redfish_api.api_deploy_os_by_sp import vmm_is_connected
from ibmc_ansible.ibmc_redfish_api.api_deploy_os_by_sp import un_mount_file
from ibmc_ansible.ibmc_redfish_api.api_deploy_os_by_sp import mount_file
from ibmc_ansible.ibmc_redfish_api.api_manage_boot_device import get_boot_device
from ibmc_ansible.ibmc_redfish_api.api_manage_boot_device import set_boot_device
from ibmc_ansible.ibmc_redfish_api.api_power_manager import manage_power
from ibmc_ansible.ibmc_redfish_api.api_power_manager import get_power_status
from ibmc_ansible.utils import set_result

SERVER_CD_ERROR_CODE = {"101": "read system info failed",
                        "102": "read system info osType failed",
                        "103": "wrong params for install os",
                        "104": "copy drive or config file failed",
                        "105": "can not read node form the config file",
                        "106": "empty node in the config file",
                        "107": "save config info failed",
                        "108": "can not find the os image",
                        "109": "read the config file form cd failed",
                        "110": "read the SN info from server failed",
                        "111": "read the disk info failed",
                        "112": "read config xml failed",
                        "113": "check image cd failed ",
                        "114": "set boot order failed",
                        "115": "partition param wrong",
                        "116": "read ks file failed"
                        }
MAX_LOOP_CNT = 50
MAX_RETRY_CNT = 3
EACH_SEND_MSG_LEN = 200


def read_bmc_info_by_redfish(ibmc):
    """
     Function:

     Args:
               ibmc       (class):

     Returns:
         "result": False
         "msg": 'not run server profile yet'
     Raises:
         None
     Examples:

     Author: xwh
     Date: 2019/10/9 20:30
    """
    oem_info = ibmc.oem_info
    rets = ''
    try:
        ret = ibmc.get_manager_resource()
    except Exception as e:
        ibmc.log_error(" read bmc info failed! exception is:%s" % str(e))
        raise
    try:
        info = ret['Oem'][oem_info]['RemoteOEMInfo']
        for i in range(0, len(info)):
            rets += chr(info[i])
    except Exception as e:
        ibmc.log_error(
            "parse bmc info failed! exception is:%s ret: %s " % (str(e), str(ret)))
        raise
    return rets.strip()


def write_bmc_info_by_redfish(ibmc, infostr):
    """
     Function:
     Args:
               ibmc       (class):
               infostr    (str):
     Returns:
         "result": False
         "msg": 'not run server profile yet'
     Raises:
         Exception
     Examples:
     Author: xwh
     Date: 2019/10/9 20:30
    """
    oem_info = ibmc.oem_info
    info = [0]
    for i in range(0, len(infostr)):
        info.append(ord(infostr[i]))
    for i in range(len(infostr), 255):
        info.append(0)
    token = ibmc.get_token()
    try:
        e_tag = ibmc.get_etag(ibmc.manager_uri)
    except Exception as e:
        ibmc.log_error("get eTag failed! exception is :%s" % str(e))
        raise
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token, 'If-Match': e_tag}
    payload = {"Oem": {oem_info: {"RemoteOEMInfo": info}}}
    try:
        r = ibmc.request('PATCH', resource=ibmc.manager_uri,
                         headers=headers, data=payload, tmout=30)
        if r.status_code == 200:
            result = True
        elif r.status_code == 412:
            ibmc.log_error("write bmc info failed! auth failed! ")
            result = False
        else:
            ibmc.log_error("write bmc info failed!")
            result = False
    except Exception as e:
        ibmc.log_error("write bmc info failed! %s " % str(e))
        result = False
        raise
    return result


def clear_bmc_info_by_redfish(ibmc):
    """
     Function:
     Args:
               ibmc       (class):
     Returns:
         "result": False
         "msg": 'not run server profile yet'
     Raises:
         Exception
     Examples:

     Author: xwh
     Date: 2019/10/9 20:30
    """
    info = [0]
    oem_info = ibmc.oem_info
    for i in range(0, 255):
        info.append(0)
    token = ibmc.get_token()
    try:
        e_tag = ibmc.get_etag(ibmc.manager_uri)
    except Exception as e:
        ibmc.log_error("get eTag failed! %s" % str(e))
        raise
    headers = {'content-type': 'application/json',
               'X-Auth-Token': token, 'If-Match': e_tag}
    payload = {"Oem": {oem_info: {"RemoteOEMInfo": info}}}
    try:
        r = ibmc.request('PATCH', resource=ibmc.manager_uri,
                         headers=headers, data=payload, tmout=30)
        if r.status_code == 200:
            result = True
        elif r.status_code == 412:
            ibmc.log_error("clear bmc info failed! auth failed!")
            result = False
        else:
            ibmc.log_error("clear bmc info failed!error code: %s json : %s" % (
                str(r.status_code), str(r.json())))
            result = False
    except Exception as e:
        ibmc.log_error("clear bmc info failed! Exception is %s" % str(e))
        result = False
        raise
    return result


def deploy_os_process(ibmc, config_dic):
    """
     Function:

     Args:
               ibmc       (class):
               config_dic    (dic): config dic

     Returns:
        "result": False
        "msg": 'not run server profile yet'
     Raises:
         None
     Examples:

     Author: xwh
     Date: 2019/10/9 20:30
    """
    log_msg = None
    rets = {"result": False, "msg": "failed"}
    if config_dic.get("os_img"):
        os_img = config_dic.get("os_img")
    else:
        raise Exception(" param os_img can not be None or empty")

    if config_dic.get("os_type"):
        os_type = config_dic.get("os_type")
    else:
        raise Exception(" param os_type can not be None or empty")

    if config_dic.get("service_cd_img"):
        service_img = config_dic.get("service_cd_img")
    else:
        raise Exception(" param service_img can not be None or empty")

    xml_start = '''<?xml version="1.0" encoding="UTF-8"?>
<osInstallInfo>'''
    xml_end = "</osInstallInfo>"
    xml_body = []
    xml_body.append(xml_start)
    if "Win" in os_type:
        if config_dic.get("win_os_name"):
            xml_body.append("   <ostype>%s</ostype>" %
                            config_dic.get("win_os_name"))
        else:
            log_msg = "param win_os_name can not be None or empty,when you install windows os"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
    else:
        xml_body.append("   <ostype>%s</ostype>" % os_type)

    if config_dic.get("cd_key"):
        xml_body.append("   <cdkey>%s</cdkey>" % config_dic.get("cd_key"))
    else:
        xml_body.append("   <cdkey></cdkey>")

    if config_dic.get("password"):
        xml_body.append("   <password>%s</password>" %
                        config_dic.get("password"))
    else:
        xml_body.append("   <password></password>")

    if config_dic.get("hostname"):
        xml_body.append("   <hostname>%s</hostname>" %
                        config_dic.get("hostname"))
    else:
        xml_body.append("   <hostname></hostname>")

    if config_dic.get("language"):
        xml_body.append("   <language>%s</language>" %
                        config_dic.get("language"))
    else:
        if "Win" in os_type:
            log_msg = "param language can not be None or empty"
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
        xml_body.append("   <language></language>")

    if config_dic.get("org_name"):
        xml_body.append("   <orgname>%s</orgname>" %
                        config_dic.get("org_name"))
    else:
        xml_body.append("   <orgname></orgname>")

    if config_dic.get("position"):
        xml_body.append("   <position>%s</position>" %
                        config_dic.get("position"))
    else:
        xml_body.append("   <position></position>")

    partitions = config_dic.get("partitions")
    if partitions:
        xml_body.append("   <partitions>")
        for partition in partitions:
            if partition.get("partition"):
                xml_body.append("   <partition>%s</partition>" %
                                partition.get("partition"))
        xml_body.append("   </partitions>")
    else:
        xml_body.append("   <partitions></partitions>")

    if config_dic.get("timezone"):
        xml_body.append("   <timezone>%s</timezone>" %
                        config_dic.get("timezone"))
    else:
        xml_body.append("   <timezone></timezone>")

    if config_dic.get("mode"):
        xml_body.append("   <mode>%s</mode>" % config_dic.get("mode"))
    else:
        xml_body.append("   <mode></mode>")

    rpms = config_dic.get("rpms")
    if rpms:
        xml_body.append("   <rpms>")
        for rpm in rpms:
            if rpm.get("rpm"):
                xml_body.append("   <rpm>%s</rpm>" % rpm.get("rpm"))
        xml_body.append("   </rpms>")
    else:
        xml_body.append("   <rpms></rpms>")

    if config_dic.get("script"):
        xml_body.append("   <script>%s</script>" % config_dic.get("script"))
    else:
        xml_body.append("   <script></script>")

    if config_dic.get("software"):
        xml_body.append("   <software>%s</software>" %
                        config_dic.get("software"))
    else:
        xml_body.append("   <software></software>")

    xml_body.append(xml_end)

    config_file = "\n".join(xml_body)
    encode_cfg_str = base64.b64encode(config_file)

    # clear bmc info
    ret = clear_bmc_info_by_redfish(ibmc)
    if ret is not True:
        log_msg = " clear ibmc info file!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    # write operator and os_type to ibmc
    ret = write_bmc_info_by_redfish(ibmc, "operator:eSight;osType:" + os_type)
    if ret is not True:
        log_msg = "write operator and os_type to ibmc file!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    ret = read_bmc_info_by_redfish(ibmc)
    ibmc.log_info("read for bmc info:%s" % str(ret))

    # get vmm is connected
    ret = vmm_is_connected(ibmc)
    ibmc.log_info("vmm connect status:" + str(ret))

    # if is connected,disconnect first
    if ret is True:
        ibmc.log_info(" vmm is connect before,unmount ! ")
        un_mount_file(ibmc)
        time.sleep(5)

    # set CD as boot device
    ibmc.log_info("set boot device to CD! ")
    set_boot_dict = {'boot_target': "Cd",
                     'boot_enabled': "Once", 'boot_mode': "UEFI"}
    set_boot_device(ibmc, set_boot_dict)

    # make sure boot device is Cd
    get_boot_device(ibmc)

    # mount service iso
    r = mount_file(ibmc, service_img)
    if r is False:
        un_mount_file(ibmc)
        log_msg = "mount file failed ,please check the service image is exist or not!"
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    ret = get_power_status(ibmc)
    if "off" in ret["msg"].lower():
        ret = manage_power(ibmc, "powerOn")
    else:
        ret = manage_power(ibmc, "ForceRestart")
    if ret['result'] is True:
        ibmc.log_info("reboot system successfully!")
    else:
        log_msg = "install os failed! reboot system failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        un_mount_file(ibmc)
        return rets

    loop = 0
    loop_count = 0
    # make sure serviceCD is received operator and os_type, write successful info to BMC
    while 1:
        loop += 1
        time.sleep(20)

        if loop > MAX_LOOP_CNT:
            loop_count += 1
            if loop_count > MAX_RETRY_CNT:
                log_msg = "%s; step1 failed!" % log_msg
                set_result(ibmc.log_error, log_msg, False, rets)
                un_mount_file(ibmc)
                return rets
            # clear bmc info
            try:
                ret = clear_bmc_info_by_redfish(ibmc)
                if ret is not True:
                    log_msg = "clear Bmc Info failed ,step1 failed!"
                    set_result(ibmc.log_error, log_msg, False, rets)
                    un_mount_file(ibmc)
                    return rets
                # write operator and os_type to ibmc
                ret = write_bmc_info_by_redfish(
                    ibmc, "operator:eSight;osType:" + os_type)
                if ret is not True:
                    log_msg = "write Bmc Info failed ,step1 failed!"
                    set_result(ibmc.log_error, log_msg, False, rets)
                    un_mount_file(ibmc)
                    return rets
                set_boot_dict = {'boot_target': "Cd",
                                 'boot_enabled': "Once", 'boot_mode': "Legacy"}
                set_boot_device(ibmc, set_boot_dict)
            except Exception as e:
                ibmc.log_Info("write bmc info exception %s" % str(e))
                time.sleep(100)
                continue
            try:
                ret = get_power_status(ibmc)
                if "off" in ret["msg"].lower():
                    ret = manage_power(ibmc, "powerOn")
                else:
                    ret = manage_power(ibmc, "ForceRestart")
            except Exception as e:
                ibmc.log_info(
                    "manger power exception ,exception is : %s" % str(e))
                continue
            ibmc.log_info("reboot system again %s " % str(ret))
            loop = 0
        try:
            log_msg = ""
            ret = read_bmc_info_by_redfish(ibmc)
            ibmc.log_info(" loop: %s ret:%s" % (str(loop), str(ret)))
            if ret.find("progress:step1;result:successful") >= 0:
                ibmc.log_info("progress:step1;result:successful")
                break
            if ret.find("result:failed") >= 0:
                ibmc.log_info("progress:step1;result:failed")
                info_group = re.match(
                    r".*result:failed;errorCode:(\d+).*", ret)
                if info_group:
                    if SERVER_CD_ERROR_CODE.get(str(info_group.group(1))):
                        log_msg = SERVER_CD_ERROR_CODE.get(
                            str(info_group.group(1)))
                    else:
                        log_msg = "unknow error, error code: %s " % info_group.group(
                            1)
                else:
                    log_msg = "unknow error; ret:%s" % str(ret)
                loop_count = MAX_RETRY_CNT
                loop = MAX_LOOP_CNT
        except Exception as e:
            ibmc.log_info(" read_bmc_info_by_redfish exception :%s" % str(e))
            continue

            # start cp config file info to BMC
    ibmc.log_info("start cp config file")
    ret = clear_bmc_info_by_redfish(ibmc)
    if ret is not True:
        log_msg = "clear Bmc Info failed ,step1 failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        un_mount_file(ibmc)
        return rets
    ret = write_bmc_info_by_redfish(ibmc, "oscfg:start")
    if ret is not True:
        log_msg = "write Bmc Info failed ,step1 failed!"
        set_result(ibmc.log_error, log_msg, False, rets)
        un_mount_file(ibmc)
        return rets

    try:
        loop_write_file = 0
        while 1:
            loop_write_file += 1
            ibmc.log_info("loop_write_file: %s" % str(loop_write_file))
            loop_next = 0
            while 1:
                loop_next += 1
                ibmc.log_info("loop_next: %s" % str(loop_next))
                try:
                    ret = read_bmc_info_by_redfish(ibmc)
                except Exception as e:
                    ibmc.log_info("Exception: %s" % str(e))
                    ret = ""
                if ret.find("oscfg:next") >= 0:
                    ibmc.log_info("find oscfg:next!!!")
                    break
                if loop_next >= 20:
                    log_msg = " write os config too long,failed! "
                    set_result(ibmc.log_error, log_msg, False, rets)
                    un_mount_file(ibmc)
                    return rets
                time.sleep(10)
            if len(encode_cfg_str) > EACH_SEND_MSG_LEN:
                new_str = encode_cfg_str[0:EACH_SEND_MSG_LEN]
                encode_cfg_str = encode_cfg_str[EACH_SEND_MSG_LEN:]
            else:
                new_str = encode_cfg_str
                encode_cfg_str = ''
            if len(new_str) == EACH_SEND_MSG_LEN:
                ibmc.log_info("equal EACH_SEND_MSG_LEN")
                ret = clear_bmc_info_by_redfish(ibmc)
                if ret is not True:
                    rets['result'] = False
                    rets['msg'] = ret
                    un_mount_file(ibmc)
                    return rets
                ret = write_bmc_info_by_redfish(ibmc, "oscfg:" + new_str)
                if ret is not True:
                    rets['result'] = False
                    rets['msg'] = ret
                    un_mount_file(ibmc)
                    return rets
            else:
                ibmc.log_info("not equal EACH_SEND_MSG_LEN")
                ret = clear_bmc_info_by_redfish(ibmc)
                if ret is not True:
                    rets['result'] = False
                    rets['msg'] = ret
                    un_mount_file(ibmc)
                    return rets
                ret = write_bmc_info_by_redfish(ibmc, "oscfg:%s:end" % new_str)
                if ret is not True:
                    rets['result'] = False
                    rets['msg'] = ret
                    un_mount_file(ibmc)
                    return rets
                break
            if loop_write_file >= 50:
                log_msg = " write os config too long,failed! "
                set_result(ibmc.log_error, log_msg, False, rets)
                un_mount_file(ibmc)
                return rets
    except Exception as e:
        log_msg = "  write config failed! error info: %s " % str(e)
        set_result(ibmc.log_error, log_msg, False, rets)
        un_mount_file(ibmc)
        return rets

    loop_step2 = 0
    while 1:
        loop_step2 += 1
        time.sleep(5)
        if loop_step2 > MAX_LOOP_CNT:
            log_msg = "progress:setp2 failed!"
            set_result(ibmc.log_error, log_msg, False, rets)
            un_mount_file(ibmc)
            return rets
        try:
            ret = read_bmc_info_by_redfish(ibmc)
        except Exception as e:
            ibmc.log_info("step2  exception: %s" % str(e))
            continue
        if ret.find("progress:step2;result:successful;errorCode:0") >= 0:
            ibmc.log_info("progress:step2;result:successful;")
            break
        elif ret.find("result:failed") != -1:
            info_group = re.match(r".*result:failed;errorCode:(\d+).*", ret)
            if info_group:
                if SERVER_CD_ERROR_CODE.get(str(info_group.group(1))):
                    log_msg = SERVER_CD_ERROR_CODE.get(
                        str(info_group.group(1)))
                else:
                    log_msg = "unknow error,error code: %s" % info_group.group(
                        1)
            else:
                log_msg = "unknow error; ret:%s" % str(ret)
            log_msg = "%s; install OS %s  failed! " % (log_msg, os_type)
            set_result(ibmc.log_error, log_msg, False, rets)
            return rets
        else:
            ibmc.log_info("loop_step2:%s ret:%s" % (str(loop_step2), str(ret)))

    # make sure the service ISO is disconnect!
    time.sleep(15)
    ret = vmm_is_connected(ibmc)
    ibmc.log_info("os is connected:%s" % str(ret))
    if ret is True:
        un_mount_file(ibmc)
    # make sure OS image is mounted!!!!
    r = mount_file(ibmc, os_img)
    if r is False:
        un_mount_file(ibmc)
        log_msg = "install OS %s  failed! please check the OS image is exist or not!" % os_type
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets

    ibmc.log_info("mount os image result: %s" % str(ret))
    time.sleep(20)

    ret = clear_bmc_info_by_redfish(ibmc)
    if ret is not True:
        set_result(ibmc.log_error, str(ret), False, rets)
        un_mount_file(ibmc)
        return rets
    ret = write_bmc_info_by_redfish(ibmc, "osinstall:start")
    if ret is not True:
        set_result(ibmc.log_error, str(ret), False, rets)
        un_mount_file(ibmc)
        return rets
    ibmc.log_info("start install os")

    try:
        loop_install = 0
        while 1:
            loop_install += 1
            time.sleep(100)
            if loop_install >= MAX_LOOP_CNT:
                log_msg = "time out; install OS %s  failed! " % os_type
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
            try:
                log_msg = ""
                ret = read_bmc_info_by_redfish(ibmc)
            except Exception as e:
                ibmc.log_info(
                    "read bmc info exception ! exception  is:%s" % str(e))
                continue
            ibmc.log_info("loop_install: %s install os: %s" %
                          (str(loop_install), str(ret)))

            if ret.find("result:5") != -1:
                log_msg = "install OS %s  successfully! " % os_type
                set_result(ibmc.log_info, log_msg, True, rets)
                return rets
            elif ret.find("result:failed") != -1:
                info_group = re.match(
                    r".*result:failed;errorCode:(\d+).*", ret)
                if info_group:
                    if SERVER_CD_ERROR_CODE.get(str(info_group.group(1))):
                        log_msg = SERVER_CD_ERROR_CODE.get(
                            str(info_group.group(1)))
                    else:
                        log_msg = "unknow error error code: %s " % info_group.group(
                            1)
                else:
                    log_msg = "unknow error; ret:%s" % str(ret)
                log_msg = "%s; install OS %s  failed! " % (log_msg, os_type)
                set_result(ibmc.log_error, log_msg, False, rets)
                return rets
            else:
                continue
    except Exception as e:
        log_msg = "install OS %s  failed! error info: %s  " % (os_type, str(e))
        set_result(ibmc.log_error, log_msg, False, rets)
        return rets
    finally:
        un_mount_file(ibmc)
