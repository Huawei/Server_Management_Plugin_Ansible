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
import re
import time
import requests

from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH
from ibmc_ansible.utils import set_result

STRIPE_SIZE = [65536, 131072, 262144, 524288, 1048576]

RAID_LEVEL = ["RAID0", "RAID1", "RAID5", "RAID6", "RAID10", "RAID50", "RAID60"]

DF_READ_POLICY = {
    "noreadahead": "NoReadAhead",
    "readahead": "ReadAhead"
}

DF_WRITE_POLICY = {
    "writethrough": "WriteThrough",
    "writebackwithbbu": "WriteBackWithBBU",
    "writeback": "WriteBack"
}

DF_CACHE_POLICY = {
    "cachedio": "CachedIO",
    "directio": "DirectIO"
}

ACCESS_POLICY = {
    "readwrite": "ReadWrite",
    "readonly": "ReadOnly",
    "blocked": "Blocked"
}

DISK_CACHE_POLICY = {
    "unchanged": "Unchanged",
    "enabled": "Enabled",
    "disabled": "Disabled"
}

INIT_MODE = {
    "uninit": "UnInit",
    "quickinit": "QuickInit",
    "fullinit": "FullInit"
}

# Covert MB to byte
MB_TO_BYTE = 1048576

# Maximum length of the name
MAX_VOLUME_NAME_LEN = 15

# Span number of RAID0,RAID1,RAID5,RAID6
RAID0_SPAN_NUM = 1
# Minimum span number of RAID10,RAID50,RAID60
MIN_RAID10_SPAN_NUM = 2
# Maximum span number of RAID10,RAID50,RAID60
MAX_RAID10_SPAN_NUM = 8

# Waiting time for getting results
GET_RESULT_TIME = 120
# Waiting time for effect
EFFECT_TIME = 20
# Waiting time for start
START_TIME = 5
# Waiting time for next loop
SLEEP_TIME = 2


def get_raid(ibmc):
    """
    Function:
        Get RAID configuration
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2019/10/12 21:13
    """
    ibmc.log_info("Start get RAID configuration resource info...")
    # Initialize return information
    ret = {'result': True, 'msg': ''}
    report_msg = ''
    # Before get RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)
    # Get all storage information

    all_storage_info = get_storage(ibmc)

    # Write RAID card, Volumes, Drives to report
    root_url = "https://%s" % ibmc.ip
    try:
        for key, value in all_storage_info.items():
            # Save the msg
            report_msg += "===========================================================\n"
            report_msg += str(key) + ":\n"
            # URL of a storage resource
            url = root_url + key
            request_result_json = send_request(ibmc, url=url, message="storage resource")
            # Save the results in the dict
            value.update(request_result_json)
            # Save the msg
            report_msg += "RAIDModel:" + str(value["StorageControllers"][0]["Model"]) + "\n"
            report_msg = splice_result(ibmc, report_msg, value)
    except Exception as e:
        log_msg = str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # File to save RAID configuration resource information
    file_name = os.path.join(IBMC_REPORT_PATH, "raid", "%s_RAIDInfo.json" % str(ibmc.ip))
    # Write the result to a file
    write_result(ibmc, file_name, all_storage_info)

    ibmc.log_info("Get RAID configuration resource info successful!")
    ibmc.report_info("Get RAID configuration resource successfully! The total information is: \n %s"
                     "For more detail information please refer to %s \n" % (report_msg, file_name))

    # Update ret
    ret['result'] = True
    ret['msg'] = "Get RAID configuration resource info successful! For more detail information please refer to %s" \
                 % file_name
    return ret


def splice_result(ibmc, report_msg, value):
    """
    Function:
        Querying RAID controller card details
    Args:
        ibmc : Class that contains basic information about iBMC
        report_msg: Current report record
        value: RAID controller card information that has been queried
    Returns:
        report_msg: Updated report records
    Raises:
         None
    Date: 2021/5/29
    """
    oem_info = ibmc.oem_info
    root_url = "https://%s" % ibmc.ip
    # Initialize value
    value["VolumesInfo"] = {}
    value["DrivesInfo"] = {}
    # URL of the volumes
    volumes_url = value["Volumes"]["@odata.id"]
    url = root_url + volumes_url
    volume_dict = send_request(ibmc, url=url, message="volumes")
    value["VolumesInfo"][volumes_url] = volume_dict
    for each_volume_dict in volume_dict.get("Members"):
        # URL of the volume
        volume_url = each_volume_dict.get("@odata.id")
        url = root_url + volume_url
        volume_info = send_request(ibmc, url=url, message="volume")
        # Save the msg
        report_msg += "-" + str(volume_url).split("/")[-1] + ":\n"
        report_msg += "--RAIDLevel: %s \n" \
                      % str(volume_info["Oem"][oem_info]["VolumeRaidLevel"])
        report_msg += "--Drives:\n"
        # Get online status drive
        for each_drive in volume_info["Links"]["Drives"]:
            if each_drive == {} or each_drive is None:
                continue
            report_msg += "---" + str(each_drive["@odata.id"]).split("/")[-1] + "\n"
        value["VolumesInfo"][volumes_url][volume_url] = volume_info
    # Get drives info
    drive_list = value.get("Drives")
    # Save the msg
    report_msg += "-UnconfiguredGood Drives:\n"
    flag = False
    for each_drive in drive_list:
        # URL of the drive
        drive_url = each_drive.get("@odata.id")
        url = root_url + drive_url
        drive_info = send_request(ibmc, url=url, message="drive")
        value["DrivesInfo"][drive_url] = drive_info
        if drive_info["Oem"][oem_info]["FirmwareStatus"] == "UnconfiguredGood":
            flag = True
            drive_name = drive_info.get("Id")
            drive_id = drive_info["Oem"][oem_info]["DriveID"]
            report_msg += "-- Drive Name: %s , Drive ID: %s \n" \
                          % (str(drive_name), str(drive_id))
    if flag is False:
        report_msg += "None\n"
    return report_msg


def get_storage(ibmc):
    """
    Function:
        Obtaining RAID Storage Information
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        all_storage_info: RAID Storage Information
    Raises:
         None
    Date: 2021/5/29
    """
    url = ibmc.system_uri + "/Storages"
    message = "RAID storage resource"
    request_result_json = send_request(ibmc, url=url, message=message)
    all_storage_info = {}
    try:
        for members in request_result_json["Members"]:
            if "RAIDStorage" not in members["@odata.id"]:
                continue
            tmp_dict = {members["@odata.id"]: {}}
            all_storage_info.update(tmp_dict)
    except Exception as e:
        log_error = "Get storage resource collection info failed! " \
                    "The error info is: %s \n" % str(e)
        ibmc.log_error(log_error)
        raise Exception("The error info is: %s \n" % str(e))
    return all_storage_info


def send_request(ibmc, url=None, message=None, payload=None):
    """
    Function:
        Send a get request.
    Args:
        ibmc : Class that contains basic information about iBMC
        url: Requested URL
        message: Description of the information to be queried
        payload: Request body
    Returns:
        report_msg: Updated report records
    Raises:
         None
    Date: 2021/5/29
    """
    if payload is None:
        payload = {}
    # Obtain token
    token = ibmc.bmc_token
    # Initialize headers
    header = {'content-type': 'application/json', 'X-Auth-Token': token}
    try:
        request_result = ibmc.request('GET', resource=url, headers=header,
                                      data=payload, tmout=30)
    except Exception as e:
        msg = "Get %s info failed! The error info is: %s \n" % (message, str(e))
        ibmc.log_error(msg)
        raise Exception(msg)

    request_code = request_result.status_code
    if request_code != 200:
        msg = "Get %s info failed! The error code is: %s, " \
              "The error info is: %s \n" % \
              (message, str(request_code), str(request_result.json()))
        ibmc.log_error(msg)
        raise Exception(msg)

    request_result_json = request_result.json()
    return request_result_json


def create_raid(ibmc, raid_info):
    """
    Function:
        Create RAID configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        raid_info : User-set RAID information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
         None
    Date: 2019/10/12 17:21
    """
    ibmc.log_info("Start create RAID configuration...")

    ret = volume_verify(ibmc, raid_info)
    if not ret.get('result'):
        return ret
    # Before create RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    # Get all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)
    volumes = raid_info.get("volumes")

    # Verify User-set RAID controller ID
    for volume in volumes:
        ret = verify_storage_id(ibmc, volume, all_raid_storage_id)
        if not ret.get('result'):
            return ret

    # Init result
    result_list = []
    # Init flag
    flag = True
    for volume in volumes:
        storage_id = volume.get("storage_id")
        payload = get_create_payload(ibmc, volume)
        if payload.get('result') is False:
            return payload

        result = get_create_raid_request(ibmc, payload, storage_id)
        if result.get('result') is False:
            flag = False
        result_list.append(result)

    # parse the final result
    if flag is False:
        log_msg = "Failed to create RAID configuration! The result info is: %s" % str(
            result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Create RAID configuration successful! The result info is: %s" % str(
        result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def volume_verify(ibmc, raid_info):
    """
    Function:
        verify reason ability of user set volume
    Args:
        ibmc : Class that contains basic information about iBMC
        raid_info : user set raid information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}

    # Obtain user-configured RAID information
    volumes = raid_info.get("volumes")

    # Verify User-set RAID information
    if not isinstance(volumes, list):
        log_msg = 'The volumes is incorrect, please set it in the create_raid.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if len(volumes) == 0:
        log_msg = 'The volumes is null, please set it in the create_raid.yml file'
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    return ret


def get_create_payload(ibmc, volume):
    """
    Function:
        get payload for create raid card
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : user set volume
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    # Initialize payload
    payload = {}

    # Obtain User-set RAID controller ID
    capacity_mbyte = volume.get("capacity_mbyte")
    stripe_size = volume.get("stripe_size")

    if capacity_mbyte is not None:
        # Verify capacity is an integer
        if not isinstance(capacity_mbyte, int):
            log_msg = "The capacity must be an integer"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        # Covert to bit
        payload["CapacityBytes"] = capacity_mbyte * MB_TO_BYTE

    if stripe_size is not None:
        # Verify capacity is an integer
        if not isinstance(stripe_size, int):
            log_msg = "The stripe size must be an integer"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if stripe_size not in STRIPE_SIZE:
            log_msg = "The strip size is incorrect, it can be set to 65536, 131072, 262144, 524288 or 1048576"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        payload["OptimumIOSizeBytes"] = stripe_size

    oem = create_oem(ibmc, volume)
    if oem.get('result') is False:
        return oem

    oem_info = ibmc.oem_info
    payload["Oem"] = {oem_info: oem.get('msg')}
    return payload


def cache_flag(ibmc, volume):
    """
    Function:
        get user set cache flag
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : user set volume
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    cachecade_flag = volume.get("cachecade_flag")
    if cachecade_flag is not None:
        # Verify cachecade flag
        if isinstance(cachecade_flag, bool):
            ret["msg"] = cachecade_flag
            return ret
        else:
            log_msg = "The cachecade flag is incorrect, it can be set to True or False"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    return ret


def get_drive_list(ibmc, volume):
    """
    Function:
        get user set drive list
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : user set volume
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    drives = volume.get("drives")
    if not drives:
        log_msg = "The drives is a mandatory parameter and cannot be empty"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    drive_list = []
    try:
        for drive_id in drives.split(","):
            if drive_id != "":
                drive_list.append(int(drive_id.strip()))
    except Exception as e:
        log_msg = "The drives is incorrect! The error info is: %s" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    ret["msg"] = drive_list
    return ret


def create_oem(ibmc, volume):
    """
    Function:
        get oem for create raid card
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : user set volume
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    # Initialize a dict
    oem = {}
    cachecade_flag = cache_flag(ibmc, volume)
    if cachecade_flag.get('result') is False:
        return cachecade_flag
    elif cachecade_flag.get('result') and cachecade_flag.get('msg') != '':
        oem["CreateCacheCadeFlag"] = cachecade_flag.get('msg')

    drives = get_drive_list(ibmc, volume)
    if drives.get('result') is False:
        return drives
    oem["Drives"] = drives.get('msg')

    volume_raid_level = get_volume_raid_level(ibmc, volume)
    if volume_raid_level.get('result') is False:
        return volume_raid_level
    oem["VolumeRaidLevel"] = volume_raid_level.get('msg')

    volume_name = get_volume_name(ibmc, volume)
    if volume_name.get('result') is False:
        return volume_name
    elif volume_name.get('result') is True and volume_name.get('msg') != '':
        oem["VolumeName"] = volume_name.get('msg')

    span_num = volume.get("span_num")
    if span_num is not None:
        ret = verify_volume_raid_level(ibmc, span_num, volume_raid_level)
        if not ret.get('result'):
            return ret
        oem["SpanNumber"] = span_num

    init_mode = volume.get("init_mode")
    if init_mode:
        init_mode = INIT_MODE.get(str(init_mode).lower())
        if init_mode not in INIT_MODE.values():
            log_msg = 'The init mode is incorrect, It should be in %s.' % INIT_MODE
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        oem["InitializationMode"] = init_mode

    common = common_oem(ibmc, volume)
    if common.get('result') is False:
        return common

    oem.update(common.get('msg'))
    ret['msg'] = oem
    return ret


def get_volume_raid_level(ibmc, volume):
    """
    Function:
        get user set volume raid level
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : user set volume
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    volume_raid_level = volume.get("volume_raid_level")
    if not volume_raid_level:
        log_msg = "The raid level is a mandatory parameter and cannot be empty"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    volume_raid_level = volume_raid_level.upper()
    if volume_raid_level not in RAID_LEVEL:
        log_msg = 'The raid level is incorrect, It should be in %s.' % RAID_LEVEL
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    ret['msg'] = volume_raid_level
    return ret


def verify_volume_raid_level(ibmc, span_num, volume_raid_level):
    """
    Function:
        verify reason ability of user set volume raid level
    Args:
        ibmc : Class that contains basic information about iBMC
        span_num: number of available span on server
        volume_raid_level : user set raid level
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    # Verify span num is an integer
    if not isinstance(span_num, int):
        log_msg = "The span num must be an integer"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if volume_raid_level in ["RAID0", "RAID1", "RAID5", "RAID6"]:
        if span_num != RAID0_SPAN_NUM:
            log_msg = "Set this parameter to %s when creating a RAID0, RAID1, RAID5, or RAID6 array" % \
                      str(RAID0_SPAN_NUM)
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    if volume_raid_level in ["RAID10", "RAID50", "RAID60"]:
        if span_num < MIN_RAID10_SPAN_NUM or span_num > MAX_RAID10_SPAN_NUM:
            log_msg = "Set this parameter to a value from %s to %s " \
                      "when creating a RAID10, RAID50, or RAID60 array" % \
                      (str(MIN_RAID10_SPAN_NUM), str(MAX_RAID10_SPAN_NUM))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    return ret


def verify_storage_id(ibmc, volume, all_raid_storage_id):
    """
    Function:
        verify reason ability of storage id
    Args:
        ibmc : Class that contains basic information about iBMC
        volume: user set volume
        all_raid_storage_id : user set raid info
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    storage_id = volume.get("storage_id")
    if not storage_id:
        log_msg = "The RAID storage id cannot be empty"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    if storage_id not in all_raid_storage_id:
        log_msg = "The RAID storage id: %s does not exist" % storage_id
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    return ret


def create_raid_request(ibmc, payload, storage_id):
    """
    Function:
        Send create RAID configuration request
    Args:
        ibmc : Class that contains basic information about iBMC
        payload : Request message body
        storage_id : RAID controller ID
    Returns:
        request_result : Create RAID request info
    Raises:
        Create RAID configuration failed!
    Date: 2019/11/9 14:36
    """
    # URL of the RAID controller
    url = "%s/Storages/%s/Volumes" % (ibmc.system_uri, str(storage_id))

    # Obtain token
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    try:
        # Create RAID configuration by POST method
        request_result = ibmc.request('POST', resource=url, headers=headers,
                                      data=payload, tmout=30)
    except Exception as e:
        ibmc.log_error("Send create RAID configuration request failed! "
                       "The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException(
            "Create RAID configuration failed! The error info is: %s" % str(e))

    return request_result


def get_create_raid_request(ibmc, payload, storage_id):
    """
    Function:
        Get create RAID request
    Args:
        ibmc : Class that contains basic information about iBMC
        payload : Request message body
        storage_id : RAID controller ID
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/13 22:15
    """
    # Init ret
    ret = {'result': True, 'msg': ''}

    try:
        # Send create RAID request
        request_result = create_raid_request(ibmc, payload, storage_id)
        request_result_json = request_result.json()
        if request_result.status_code == 202:
            task_url = request_result_json.get("@odata.id")
            ibmc.log_info(
                "Create RAID configuration task url is: %s" % str(task_url))
        else:
            log_msg = "Failed to create RAID: %s, The error code is: %s, The error info is: %s" \
                      % (storage_id, str(request_result.status_code),
                         (request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "Failed to create RAID: %s, The error info is: %s" \
                  % (storage_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Wait for task start
    time.sleep(START_TIME)

    loop_time = 0
    while True:
        if loop_time > GET_RESULT_TIME:
            log_msg = "Failed to create RAID: %s" % storage_id
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        # Get task result
        try:
            task_result = get_task_status(ibmc, task_url)
        except Exception as e:
            ibmc.log_error("Get task status exception, "
                           "The error info is: %s, continue..." % str(e))
            continue

        loop_time += 1
        if task_result[0].find("Successful") != -1:
            log_msg = "Create RAID configuration successful! The RAID id is: %s" % storage_id
            set_result(ibmc.log_info, log_msg, True, ret)
            # Wait for effect
            time.sleep(EFFECT_TIME)
            break
        else:
            time.sleep(SLEEP_TIME)

    return ret


def delete_raid(ibmc, raid_info):
    """
    Function:
        Delete RAID configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        raid_info : User-set RAID information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 15:15
    """
    ibmc.log_info("Start delete RAID configuration...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Before delete RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    get_storage_id = get_storage_id_list(ibmc, raid_info)
    if get_storage_id.get('result') is False:
        return get_storage_id
    else:
        storage_id_list = get_storage_id.get('msg')
    # Save Volume id
    volume_id_dict = {}
    # Obtain User-set volume id
    volume_id = raid_info.get("volume_id")
    for storage_id in storage_id_list:
        update_volume = update_volume_id(ibmc, volume_id, storage_id)
        if update_volume.get('result') is False:
            return update_volume
        volume_id_dict.update(update_volume.get('msg'))

    result_list = []
    flag = True
    for storage_id in volume_id_dict.keys():
        volume_list = volume_id_dict.get(storage_id)
        for volume_id in volume_list:
            result = delete_raid_request(ibmc, storage_id, volume_id)
            if result["result"] is False:
                flag = False
            result_list.append(result)

    # Pares the final result
    if flag is False:
        log_msg = "Failed to delete RAID configuration, The result is: %s" % str(
            result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Delete RAID configuration successful!, The result is: %s" \
              % str(result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def get_storage_id_list(ibmc, raid_info):
    """
    Function:
        get user set storage id list
    Args:
        ibmc : Class that contains basic information about iBMC
        raid_info : user set raid info
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    # Save RAID storage id
    storage_id_list = []
    # Save not exist RAID storage id
    not_exist_storage_id_list = []
    # Obtain all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)
    # Obtain User-set RAID controller id
    storage_id = raid_info.get("storage_id")
    if storage_id == "all":
        storage_id_list = all_raid_storage_id
        ret['msg'] = storage_id_list
        return ret
    elif storage_id == "":
        log_msg = "The RAID storage id is empty, please modify it in the delete_raid.yml file"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    elif storage_id.find("RAIDStorage") == -1:
        log_msg = "The RAID storage id: %s is incorrect, please modify it " \
                  "in the delete_raid.yml file" % str(storage_id)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Init flag
    flag = True
    # Verify RAID controller id
    raid_list = storage_id.split(",")
    for raid in raid_list:
        if raid != "" and (raid.strip() in all_raid_storage_id):
            storage_id_list.append(raid.strip())
        else:
            not_exist_storage_id_list.append(raid.strip())
            flag = False
    if flag is False:
        log_msg = "The RAID storage id: %s not exist, The available parameters are: %s, " \
                  "please modify it in the delete_raid.yml file" % \
                  (str(not_exist_storage_id_list), str(all_raid_storage_id))
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    else:
        ret['msg'] = storage_id_list
        return ret


def update_volume_id(ibmc, volume_id, storage_id):
    """
    Function:
        Update Volume id list
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_id : RAID controller id
        volume_id : Volume id
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    ret = {'result': True, 'msg': ''}
    # Obtain all volume id under RAID controller
    all_volume_id = get_all_volume_id(ibmc, storage_id)
    volume_id_list = []
    volume_id_dict = {}
    # Save not exist volume id
    not_exist_volume_id_list = []
    # Init flag
    flag = True
    # Verify volume id
    if volume_id == "all":
        volume_id_dict[storage_id] = all_volume_id
    elif volume_id.find("LogicalDrive") != -1:
        volume_list = volume_id.split(",")
        for volume in volume_list:
            if volume != "" and (volume.strip() in all_volume_id):
                volume_id_list.append(volume.strip())
            else:
                not_exist_volume_id_list.append(volume.strip())
                flag = False
        if flag is False:
            log_msg = "The volume id: %s not exist, The available parameters are: %s, " \
                      "please modify it in the delete_raid.yml file" % \
                      (str(not_exist_volume_id_list), str(all_volume_id))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        volume_id_dict[storage_id] = volume_id_list
    elif storage_id == "":
        log_msg = "The volume id is empty, please modify it in the delete_raid.yml file"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    else:
        log_msg = "The volume id: %s is incorrect, please modify it in the delete_raid.yml file" % str(
            volume_id)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    ret['msg'] = volume_id_dict
    return ret


def delete_raid_request(ibmc, storage_id, volume_id):
    """
    Function:
        Send request to delete raid
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_id : RAID controller id
        volume_id : Volume id
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/12 22:07
    """
    # init result
    ret = {'result': True, 'msg': ''}
    # URL of the volume
    url = "%s/Storages/%s/Volumes/%s" % (ibmc.system_uri, storage_id, volume_id)
    # Obtain token
    token = ibmc.bmc_token
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    # Init payload
    payload = {}
    storage_volume_id = storage_id + "/" + volume_id

    try:
        # Delete RAID configuration by DELETE method
        request_result = ibmc.request('DELETE', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        request_result_json = request_result.json()
        if request_code == 202:
            task_url = request_result_json.get("@odata.id")
            ibmc.log_info(
                "Delete RAID configuration task url is: %s" % str(task_url))
        else:
            log_msg = "Failed to delete LD: %s, The error code is: %s, The error info is: %s" % \
                      (storage_volume_id, str(request_code),
                       str(request_result_json))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "Failed to delete LD: %s, The error info is: %s" \
                  % (storage_volume_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    ret = wait_task_start(ibmc, storage_volume_id, task_url)
    return ret


def wait_task_start(ibmc, storage_volume_id, task_url):
    """
    Function:
        wait task start for
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_volume_id : User-set volume id
        task_url : url of task
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ret = {'result': True, 'msg': ''}
    # Wait for task start
    time.sleep(START_TIME)
    loop_time = 0
    while True:
        if loop_time > GET_RESULT_TIME:
            log_msg = "Failed to delete LD: %s" % storage_volume_id
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        # Get task result
        try:
            task_result = get_task_status(ibmc, task_url)
        except Exception as e:
            ibmc.log_error("Get task status exception, "
                           "The error info is: %s, continue..." % str(e))
            continue

        loop_time += 1
        if task_result[0].find("Successful") != -1:
            log_msg = "Delete LD: %s successful" % storage_volume_id
            set_result(ibmc.log_info, log_msg, True, ret)
            # Wait for effect
            time.sleep(EFFECT_TIME)
            break
        else:
            time.sleep(SLEEP_TIME)
    return ret


def modify_raid(ibmc, raid_info):
    """
    Function:
        Modify RAID configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        raid_info : User-set RAID information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ibmc.log_info("Start modify RAID configuration...")

    ret = volume_verify(ibmc, raid_info)
    if not ret.get('result'):
        return ret

    # Get all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)
    volumes = raid_info.get("volumes")

    # Verify User-set RAID controller id and volume id
    for volume in volumes:
        # Obtain User-set RAID controller ID
        ret = verify_storage_id(ibmc, volume, all_raid_storage_id)
        if not ret.get('result'):
            return ret
        storage_id = volume.get("storage_id")
        # Save all volume
        all_volume_id = get_all_volume_id(ibmc, storage_id)

        # Obtain User-set RAID controller ID
        volume_id = volume.get("volume_id")
        if not volume_id:
            log_msg = "The volume id cannot be empty"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if volume_id not in all_volume_id:
            log_msg = "The volume id: %s does not exist" % volume_id
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # init result
    result_list = []
    flag = True
    oem_info = ibmc.oem_info

    for volume in volumes:
        # Initialize payload
        payload = {}

        # Obtain User-set RAID controller ID
        storage_id = volume.get("storage_id")
        volume_id = volume.get("volume_id")
        oem = get_modify_oem(ibmc, volume)
        if not oem.get('result'):
            return oem

        payload["Oem"] = {oem_info: oem.get('msg')}
        # Get modify raid result
        result = modify_raid_request(ibmc, payload, storage_id, volume_id)
        if result["result"] is True:
            # Wait for effect
            time.sleep(EFFECT_TIME)
        else:
            flag = False
        result_list.append(result)

    # Pares the final result
    if flag is False:
        log_msg = "Failed to modify RAID configuration, The result is: %s" % str(
            result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Modify RAID configuration successful!, The result is: %s" \
              % str(result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def common_oem(ibmc, volume):
    """
    Function:
        Get common oem information for creat raid or modify raid
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : User-set volume information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ret = {'result': True, 'msg': ''}
    oem = {}
    df_read_policy = volume.get("df_read_policy")
    if df_read_policy:
        df_read_policy = DF_READ_POLICY.get(str(df_read_policy).lower())
        if df_read_policy not in DF_READ_POLICY.values():
            log_msg = 'The default read policy is incorrect, It should be in %s.' % DF_READ_POLICY
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        oem["DefaultReadPolicy"] = df_read_policy

    df_write_policy = volume.get("df_write_policy")
    if df_write_policy:
        df_write_policy = DF_WRITE_POLICY.get(str(df_write_policy).lower())
        if df_write_policy not in DF_WRITE_POLICY.values():
            log_msg = 'The default write policy is incorrect, It should be in %s' % DF_WRITE_POLICY
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        oem["DefaultWritePolicy"] = df_write_policy

    df_cache_policy = volume.get("df_cache_policy")
    if df_cache_policy:
        df_cache_policy = DF_CACHE_POLICY.get(str(df_cache_policy).lower())
        if df_cache_policy not in DF_CACHE_POLICY.values():
            log_msg = 'The default cache policy is incorrect, It should be in %s.' % DF_CACHE_POLICY
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        oem["DefaultCachePolicy"] = df_cache_policy

    access_policy = volume.get("access_policy")
    if access_policy:
        access_policy = ACCESS_POLICY.get(str(access_policy).lower())
        if access_policy not in ACCESS_POLICY.values():
            log_msg = 'The access policy is incorrect, It should be in %s.' % ACCESS_POLICY
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        oem["AccessPolicy"] = access_policy

    disk_cache_policy = volume.get("disk_cache_policy")
    if disk_cache_policy:
        disk_cache_policy = DISK_CACHE_POLICY.get(
            str(disk_cache_policy).lower())
        if disk_cache_policy not in DISK_CACHE_POLICY.values():
            log_msg = 'The disk cache policy is incorrect, It should be in %s.' % DISK_CACHE_POLICY
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        oem["DriveCachePolicy"] = disk_cache_policy
    ret['msg'] = oem
    return ret


def get_volume_name(ibmc, volume):
    """
    Function:
        Get user set volume name
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : User-set volume information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ret = {'result': True, 'msg': ''}
    volume_name = volume.get("volume_name")
    if volume_name is not None:
        try:
            if len(volume_name) > MAX_VOLUME_NAME_LEN:
                log_msg = "Invalid length of the volume name, the maximum length is %s" % str(
                    MAX_VOLUME_NAME_LEN)
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
        except Exception as e:
            ibmc.log_error('The volume name is illegal! '
                           'The error info is: %s \n' % str(e))
            raise ValueError(
                'The volume name is illegal! The error info is: %s' % str(e))
        ret['msg'] = volume_name
    return ret


def get_modify_oem(ibmc, volume):
    """
    Function:
        Get oem information for modify RAID configuration
    Args:
        ibmc : Class that contains basic information about iBMC
        volume : User-set volume information
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:04
    """
    ret = {'result': True, 'msg': ''}
    oem = {}
    volume_name = get_volume_name(ibmc, volume)
    if volume_name.get('result') is False:
        return volume_name
    elif volume_name.get('result') and not volume_name.get('msg') != '':
        oem["VolumeName"] = volume_name.get('msg')

    boot_enable = volume.get("boot_enable")
    if boot_enable is not None:
        if boot_enable is True:
            oem["BootEnable"] = True
        else:
            log_msg = 'The boot enabled is incorrect, It can only be true'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    bgi_enable = volume.get("bgi_enable")
    if bgi_enable is not None:
        if isinstance(bgi_enable, bool):
            oem["BGIEnable"] = bgi_enable
        else:
            log_msg = 'The bgi enabled is incorrect, It should be True or False'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    ssd_cache_enable = volume.get("ssd_cache_enable")
    if ssd_cache_enable is not None:
        if isinstance(ssd_cache_enable, bool):
            oem["SSDCachingEnable"] = ssd_cache_enable
        else:
            log_msg = 'The ssd cache enabled is incorrect, It should be True or False'
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    common = common_oem(ibmc, volume)
    if common.get('result') is False:
        return common
    else:
        oem.update(common.get('msg'))

    ret['msg'] = oem
    return ret


def modify_raid_request(ibmc, payload, storage_id, volume_id):
    """
    Function:
        Send modify RAID configuration request
    Args:
        ibmc : Class that contains basic information about iBMC
        payload : Request message body
        storage_id : User-set RAID controller ID
        volume_id : User-set Volume ID
    Returns:
        ret : a dict of task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2019/11/9 18:55
    """
    # init result
    ret = {'result': True, 'msg': ''}
    # URL of the volume
    url = "%s/Storages/%s/Volumes/%s" % (ibmc.system_uri, storage_id, volume_id)

    # Obtain token
    token = ibmc.bmc_token
    # Obtain etag
    etag = ibmc.get_etag(url)
    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token,
               'If-Match': etag}

    storage_volume_id = storage_id + "/" + volume_id
    try:
        # Modify RAID configuration by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Modify RAID: %s configuration successful!" % storage_volume_id
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Failed to modify RAID: %s, The error code is: %s, The error info is: %s." % \
                      (storage_volume_id, str(request_code),
                       str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "Failed to modify RAID: %s, The error info is: %s." % (
            storage_volume_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def get_all_storage_id(ibmc):
    """
    Function:
        Get all RAID storage information
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        all_raid_storage_id : all RAID storage id, Example: [RAIDStorage0,RAIDStorage1]
    Raises:
        Get RAID storage resource info failed! or
        Get RAID storage id failed!
    Date: 2019/11/4 20:52
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token
    # URL of the NTP service
    url = ibmc.system_uri + "/Storages"
    # Initialize headers
    headers = {'X-Auth-Token': token}
    # Initialize payload
    payload = {}

    try:
        # Obtain the NTP configuration resource information through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            msg = "Get RAID storage resource info failed! The error code is: %s, " \
                  "The error info is: %s \n" % (str(request_code), str(request_result.json()))
            ibmc.log_error(msg)
            raise Exception(msg)
    except Exception as e:
        msg = "Get RAID storage resource info failed! The error info is: %s \n" % str(e)
        ibmc.log_error(msg)
        raise requests.exceptions.RequestException(msg)

    request_result_json = request_result.json()
    all_raid_storage_id = []
    try:
        for members in request_result_json.get("Members"):
            raid_storage_url = members.get("@odata.id")
            all_raid_storage_id.append(str(raid_storage_url).split("/")[-1])
    except Exception as e:
        msg = "Get RAID storage id failed! The error info is: %s \n" % str(e)
        ibmc.log_error(msg)
        raise Exception(msg)
    return all_raid_storage_id


def get_all_volume_id(ibmc, storage_id):
    """
    Function:
        Get all volume of a RAID controller
    Args:
        ibmc : Class that contains basic information about iBMC
        storage_id : RAID controller id
    Returns:
        all_volume_id : all volume id, example: [LogicalDrive0,LogicalDrive1]
    Raises:
        Send get volume request failed! or
        Get all volume id failed!
    Date: 2019/11/9 18:22
    """
    # URL of the volume
    url = "%s/Storages/%s/Volumes" % (ibmc.system_uri, str(storage_id))

    # Obtain token
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}
    try:
        # Get volume by POST method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code != 200:
            msg = "Get all volume info failed! The error code is: %s, " \
                  "The error info is: %s \n" \
                  % (str(request_code), str(request_result.json()))
            ibmc.log_error(msg)
            raise requests.exceptions.RequestException(msg)
    except Exception as e:
        msg = "Get all volume info failed! The error info is: %s" % str(e)
        ibmc.log_error(msg)
        raise Exception(msg)

    # Save all volume
    all_volume_id = []
    request_result_json = request_result.json()
    try:
        for members in request_result_json.get("Members"):
            volume_url = members.get("@odata.id")
            all_volume_id.append(str(volume_url).split("/")[-1])
    except Exception as e:
        msg = "Get all volume id failed! The error info is: %s \n" % str(e)
        ibmc.log_error(msg)
        raise Exception(msg)
    return all_volume_id


def get_task_status(ibmc, task_url):
    """
    Function:
        Get task status
    Args:
        ibmc : Class that contains basic information about iBMC
        task_url : URL of task
    Returns:
        result : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        Get task resource failed!
    Date: 2019/11/9 15:34
    """
    # URL of the NTP service
    url = "https://%s" % ibmc.ip + task_url

    # Obtain token
    token = ibmc.bmc_token

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    # Initialize result
    result = []

    try:
        # Get task result by GET method
        request_result = ibmc.request('GET', resource=url, headers=headers,
                                      data=payload, tmout=30)
    except Exception as e:
        msg = "Get task resource failed! The error info is: %s" % str(e)
        ibmc.log_error(msg)
        raise requests.exceptions.RequestException(msg)

    try:
        if request_result.status_code != 200:
            result.append("Failed")
            result.append("Unknown error!")
            return result

        request_result_json = request_result.json()
        ibmc.log_info("The task result is: %s" % request_result_json)
        task_status = request_result_json[u'TaskState']

        if task_status == "Running":
            result.append("Running")
        elif task_status == "Completed" and \
                re.search("successfully", request_result_json['Messages']['Message'], re.I):
            result.append("Successful")
            result.append(request_result_json['Messages']['MessageArgs'][0])
        else:
            result.append(task_status)
            result.append(request_result_json['Messages']['Message'])

    except Exception as e:
        result.append("Exception")
        result.append(str(e))

    ibmc.log_info("The task result is: %s" % str(result))
    return result


def check_power_state(ibmc):
    """
    Function:
        Check server power state
    Args:
        ibmc : Class that contains basic information about iBMC
    Returns:
        None
    Raises:
        Get RAID configuration resource info failed! or
        The server has been powered off, Retry after powering on the server
    Date: 2019/11/5 21:52
    """
    systems_source = ibmc.get_systems_resource()
    try:
        power_state = systems_source.get("PowerState")
    except Exception as e:
        msg = "Get system power state failed! The error info is: %s \n" % str(
            e)
        ibmc.log_error(msg)
        raise Exception(msg)

    if power_state != "On":
        msg = "The server has been powered off, Retry after powering on the server"
        ibmc.log_error(msg)
        raise Exception(msg)
