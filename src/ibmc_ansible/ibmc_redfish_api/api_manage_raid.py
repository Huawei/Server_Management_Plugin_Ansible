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
import requests

from ibmc_ansible.utils import set_result, IBMC_REPORT_PATH, write_result

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
              ibmc              (class):   Class that contains basic information about iBMC
    Returns:
         {"result": True, "msg": "Get RAID configuration resource info successful!"}
    Raises:
         None
    Examples:
         None
    Author:
    Date: 2019/10/12 21:13
    """
    ibmc.log_info("Start get RAID configuration resource info...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}
    report_msg = ""

    # Before get RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    # Get all storage information
    all_storage_info = {}
    request_result_json = get_all_storage_url(ibmc)
    try:
        for members in request_result_json["Members"]:
            if "RAIDStorage" not in members["@odata.id"]:
                continue
            tmp_dict = {members["@odata.id"]: {}}
            all_storage_info.update(tmp_dict)
    except Exception as e:
        ibmc.log_error("Get storage resource collection info failed! The error info is: %s \n" % str(e))
        ret['result'] = False
        ret['msg'] = "Get RAID configuration resource info failed!"
        return ret

    # Write RAID card, Volumes, Drives to report
    root_url = "https://%s" % ibmc.ip
    try:
        for key, value in all_storage_info.items():
            # Save the msg
            report_msg += "===========================================================\n"
            report_msg += str(key) + ":\n"
            # Obtain token
            token = ibmc.bmc_token
            # URL of a storage resource
            url = root_url + key
            # Initialize headers
            headers = {'content-type': 'application/json', 'X-Auth-Token': token}
            # Initialize payload
            payload = {}

            try:
                # Querying a storage resource information through the GET method
                request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
            except Exception as e:
                ibmc.log_error("Send get a storage resource request failed! The error info is: %s \n" % str(e))
                ret['result'] = False
                ret['msg'] = "Get RAID configuration resource info failed!"
                return ret
            if request_result.status_code == 200:
                # Save the results in the dict
                value.update(request_result.json())
                # Save the msg
                report_msg += "RAIDModel:" + str(value["StorageControllers"][0]["Model"]) + "\n"
                # Initialize value
                value["AssociatedCardInfo"] = {}
                value["VolumesInfo"] = {}
                value["DrivesInfo"] = {}

                # URL of the RAID card
                raid_card_url = value["StorageControllers"][0]["Oem"]["Huawei"]["AssociatedCard"]["@odata.id"]
                url = root_url + raid_card_url
                try:
                    # Querying associated RAID card information through the GET method
                    request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
                except Exception as e:
                    ibmc.log_error(
                        "Send get associated RAID card info request failed! The error info is: %s \n" % str(e))
                    ret['result'] = False
                    ret['msg'] = "Get RAID configuration resource info failed!"
                    return ret
                if request_result.status_code == 200:
                    raid_dict = {str(raid_card_url): request_result.json()}
                    value["AssociatedCardInfo"].update(raid_dict)
                else:
                    log_msg = "Get associated RAID card info failed! The error code is: %s, The error info is: %s" \
                              % (str(request_result.status_code), str(request_result.json()))
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret

                # URL of the volumes
                volumes_url = value["Volumes"]["@odata.id"]
                url = root_url + volumes_url
                try:
                    # Querying volumes information through the GET method
                    request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
                except Exception as e:
                    ibmc.log_error("Send get volumes info request failed! The error info is: %s \n" % str(e))
                    ret['result'] = False
                    ret['msg'] = "Get RAID configuration resource info failed!"
                    return ret
                if request_result.status_code == 200:
                    volume_list = request_result.json()
                    value["VolumesInfo"][volumes_url] = volume_list
                    for each_volume_dict in volume_list["Members"]:
                        # URL of the volume
                        volume_url = each_volume_dict["@odata.id"]
                        url = root_url + volume_url
                        try:
                            # Querying volume information through the GET method
                            request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
                        except Exception as e:
                            ibmc.log_error("Send get volume info request failed! The error info is: %s \n" % str(e))
                            ret['result'] = False
                            ret['msg'] = "Get RAID configuration resource info failed!"
                            return ret
                        # Get a volume info
                        volume_info = request_result.json()
                        if request_result.status_code == 200:
                            # Save the msg
                            report_msg += "-" + str(volume_url).split("/")[-1] + ":\n"
                            report_msg += "--RAIDLevel:" + str(volume_info["Oem"]["Huawei"]["VolumeRaidLevel"]) + "\n"
                            report_msg += "--Drives:\n"
                            # Get online status drive
                            for each_drive in volume_info["Links"]["Drives"]:
                                if each_drive == {} or each_drive is None:
                                    continue
                                report_msg += "---" + str(each_drive["@odata.id"]).split("/")[-1] + "\n"
                            value["VolumesInfo"][volumes_url][volume_url] = request_result.json()
                        else:
                            log_msg = "Get volume info failed! The error code is: %s, The error info is: %s" \
                                      % (str(request_result.status_code), str(volume_info))
                            set_result(ibmc.log_error, log_msg, False, ret)
                            return ret
                else:
                    log_msg = "Get volumes info failed! The error code is: %s, The error info is: %s" \
                              % (str(request_result.status_code), str(request_result.json()))
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret

                # Get drives info
                drive_list = value["Drives"]

                # Save the msg
                report_msg += "-UnconfiguredGood Drives:\n"
                flag = False
                for each_drive in drive_list:
                    # URL of the drive
                    drive_url = each_drive["@odata.id"]
                    url = root_url + drive_url
                    try:
                        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
                    except Exception as e:
                        ibmc.log_error("Send get drive info request failed! The error info is: %s \n" % str(e))
                        ret['result'] = False
                        ret['msg'] = "Get RAID configuration resource info failed!"
                        return ret
                    if request_result.status_code == 200:
                        drive_info = request_result.json()
                        value["DrivesInfo"][drive_url] = drive_info
                        if drive_info["Oem"]["Huawei"]["FirmwareStatus"] == "UnconfiguredGood":
                            flag = True
                            drive_name = drive_info["Id"]
                            drive_id = drive_info["Oem"]["Huawei"]["DriveID"]
                            report_msg += "--" + "Drive Name: " + str(drive_name) + ", Drive ID: " + str(
                                drive_id) + "\n"
                    else:
                        log_msg = "Get drive info failed! The error code is: %s, The error info is: %s" \
                                  % (str(request_result.status_code), str(request_result.json()))
                        set_result(ibmc.log_error, log_msg, False, ret)
                        return ret

                if flag is False:
                    report_msg += "None\n"
            else:
                log_msg = "Get storage resource info failed! The error code is: %s, The error info is: %s" \
                          % (str(request_result.status_code), str(request_result.json()))
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
    except Exception as e:
        log_msg = "Get RAID configuration resource info failed! The error info is: %s \n" % str(e)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # File to save RAID configuration resource information
    file_name = os.path.join(IBMC_REPORT_PATH, "raid", str(ibmc.ip) + "_RAIDInfo.json")
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


def create_raid(ibmc, raid_info):
    """

    Function:
        Create RAID configuration
    Args:
              ibmc                    (class):    Class that contains basic information about iBMC
              raid_info               (list):     User-set RAID information
    Returns:
         {"result": True, "msg": "Create RAID configuration successful!"}
    Raises:
         None
    Examples:
         None
    Author:
    Date: 2019/10/12 17:21
    """
    ibmc.log_info("Start create RAID configuration...")

    # Initialize return information
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

    # Before create RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    # Get all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)

    # Verify User-set RAID controller ID
    for volume in volumes:
        # Obtain User-set RAID controller ID
        storage_id = volume.get("storage_id")
        if not storage_id:
            log_msg = "The RAID storage id cannot be empty"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if storage_id not in all_raid_storage_id:
            log_msg = "The RAID storage id: %s does not exist" % storage_id
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

    # Init result
    result_list = []
    # Init flag
    flag = True
    for volume in volumes:
        # Initialize payload
        payload = {}

        # Obtain User-set RAID controller ID
        storage_id = volume.get("storage_id")
        capacity_mbyte = volume.get("capacity_mbyte")
        stripe_size = volume.get("stripe_size")
        cachecade_flag = volume.get("cachecade_flag")
        drives = volume.get("drives")
        volume_raid_level = volume.get("volume_raid_level")
        volume_name = volume.get("volume_name")
        df_read_policy = volume.get("df_read_policy")
        df_write_policy = volume.get("df_write_policy")
        df_cache_policy = volume.get("df_cache_policy")
        span_num = volume.get("span_num")
        access_policy = volume.get("access_policy")
        disk_cache_policy = volume.get("disk_cache_policy")
        init_mode = volume.get("init_mode")

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

        # Initialize a dict
        oem = {}

        if cachecade_flag is not None:
            # Verify cachecade flag
            cachecade_flag = str(cachecade_flag).lower()
            if cachecade_flag == "true":
                oem["CreateCacheCadeFlag"] = True
            elif cachecade_flag == "false":
                oem["CreateCacheCadeFlag"] = False
            else:
                log_msg = "The cachecade flag is incorrect, it can be set to True or False"
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if drives:
            drive_list = []
            try:
                for drive_id in drives.split(","):
                    if drive_id != "":
                        drive_list.append(int(drive_id.strip()))
                oem["Drives"] = drive_list
            except Exception as e:
                log_msg = "The drives is incorrect! The error info is: %s" % str(e)
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
        else:
            log_msg = "The drives is a mandatory parameter and cannot be empty"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if volume_raid_level:
            volume_raid_level = volume_raid_level.upper()
            if volume_raid_level in RAID_LEVEL:
                oem["VolumeRaidLevel"] = volume_raid_level
            else:
                log_msg = 'The raid level is incorrect, It should be "RAID0", "RAID1", "RAID5", "RAID6", ' \
                          '"RAID10", "RAID50", "RAID60"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
        else:
            log_msg = "The raid level is a mandatory parameter and cannot be empty"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

        if volume_name is not None:
            try:
                if len(volume_name) > MAX_VOLUME_NAME_LEN:
                    log_msg = "Invalid length of the volume name, the maximum length is %s" % str(MAX_VOLUME_NAME_LEN)
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret
            except Exception as e:
                log_msg = 'The volume name is illegal! The error info is: %s' % str(e)
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            oem["VolumeName"] = volume_name

        if df_read_policy:
            df_read_policy = DF_READ_POLICY.get(str(df_read_policy).lower())
            if df_read_policy in DF_READ_POLICY.values():
                oem["DefaultReadPolicy"] = df_read_policy
            else:
                log_msg = 'The default read policy is incorrect, It should be "NoReadAhead", "ReadAhead"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if df_write_policy:
            df_write_policy = DF_WRITE_POLICY.get(str(df_write_policy).lower())
            if df_write_policy in DF_WRITE_POLICY.values():
                oem["DefaultWritePolicy"] = df_write_policy
            else:
                log_msg = 'The default write policy is incorrect, It should be "WriteThrough", ' \
                          '"WriteBackWithBBU", "WriteBack"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if df_cache_policy:
            df_cache_policy = DF_CACHE_POLICY.get(str(df_cache_policy).lower())
            if df_cache_policy in DF_CACHE_POLICY.values():
                oem["DefaultCachePolicy"] = df_cache_policy
            else:
                log_msg = 'The default cache policy is incorrect, It should be "CachedIO", "DirectIO"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if span_num is not None:
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
            oem["SpanNumber"] = span_num

        if access_policy:
            access_policy = ACCESS_POLICY.get(str(access_policy).lower())
            if access_policy in ACCESS_POLICY.values():
                oem["AccessPolicy"] = access_policy
            else:
                log_msg = 'The access policy is incorrect, It should be "ReadWrite", "ReadOnly", "Blocked"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if disk_cache_policy:
            disk_cache_policy = DISK_CACHE_POLICY.get(str(disk_cache_policy).lower())
            if disk_cache_policy in DISK_CACHE_POLICY.values():
                oem["DriveCachePolicy"] = disk_cache_policy
            else:
                log_msg = 'The disk cache policy is incorrect, It should be "Unchanged", "Enabled", "Disabled"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if init_mode:
            init_mode = INIT_MODE.get(str(init_mode).lower())
            if init_mode in INIT_MODE.values():
                oem["InitializationMode"] = init_mode
            else:
                log_msg = 'The init mode is incorrect, It should be "UnInit", "QuickInit", "FullInit"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        payload["Oem"] = {"Huawei": oem}

        result = get_create_raid_request(ibmc, payload, storage_id)
        if result["result"] is False:
            flag = False
        result_list.append(result)

    # parse the final result
    if flag is False:
        log_msg = "Failed to create RAID configuration! The result info is: %s" % str(result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Create RAID configuration successful! The result info is: %s" % str(result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def create_raid_request(ibmc, payload, storage_id):
    """

    Function:
        Send create RAID configuration request
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
              payload         (dict):    Request message body
              storage_id      (str):     RAID controller ID
    Returns:
        Create RAID request info
    Raises:
        Create RAID configuration failed!
    Examples:
        None
    Author:
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
        request_result = ibmc.request('POST', resource=url, headers=headers, data=payload, tmout=30)
    except Exception as e:
        ibmc.log_error("Send create RAID configuration request failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Create RAID configuration failed! The error info is: %s" % str(e))

    return request_result


def get_create_raid_request(ibmc, payload, storage_id):
    """

    Function:
        Get create RAID request
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
              payload         (dict):    Request message body
              storage_id      (str):     RAID controller ID
    Returns:
        {'result': True, 'msg': 'Create RAID configuration successful!'}
    Raises:
        None
    Examples:
        None
    Author:
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
            ibmc.log_info("Create RAID configuration task url is: %s" % str(task_url))
        else:
            log_msg = "Failed to create RAID: %s, The error code is: %s, The error info is: %s" % \
                      (storage_id, str(request_result.status_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "Failed to create RAID: %s, The error info is: %s" % (storage_id, str(e))
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
            ibmc.log_error("Get task status exception, The error info is: %s, continue..." % str(e))
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
              ibmc                    (class):    Class that contains basic information about iBMC
              raid_info               (list):     User-set RAID information
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/11/12 15:15
    """
    ibmc.log_info("Start delete RAID configuration...")

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    # Before delete RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    # Obtain all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)

    # Save RAID storage id
    storage_id_list = []
    # Save not exist RAID storage id
    not_exist_storage_id_list = []
    # Init flag
    flag = True
    # Save Volume id
    volume_id_dict = {}

    # Obtain User-set RAID controller id
    storage_id = raid_info.get("storage_id")
    if storage_id == "all":
        storage_id_list = all_raid_storage_id
    elif storage_id.find("RAIDStorage") != -1:
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
    elif storage_id == "":
        log_msg = "The RAID storage id is empty, please modify it in the delete_raid.yml file"
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret
    else:
        log_msg = "The RAID storage id: %s is incorrect, please modify it in the delete_raid.yml file" % str(storage_id)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    # Obtain User-set volume id
    volume_id = raid_info.get("volume_id")
    for storage_id in storage_id_list:
        # Obtain all volume id under RAID controller
        all_volume_id = get_all_volume_id(ibmc, storage_id)
        volume_id_list = []
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
                          (str(not_exist_volume_id_list), str(volume_id_list))
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret
            volume_id_dict[storage_id] = volume_id_list
        elif storage_id == "":
            log_msg = "The volume id is empty, please modify it in the delete_raid.yml file"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        else:
            log_msg = "The volume id: %s is incorrect, please modify it in the delete_raid.yml file" % str(volume_id)
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

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
        log_msg = "Failed to delete RAID configuration, The result is: %s" % str(result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Delete RAID configuration successful!, The result is: %s" % str(result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def delete_raid_request(ibmc, storage_id, volume_id):
    """

    Function:
        None
    Args:
              ibmc                    (class):    Class that contains basic information about iBMC
              storage_id              (class):    RAID controller id
              volume_id               (class):    Volume id
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author:
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
        request_result = ibmc.request('DELETE', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        request_result_json = request_result.json()
        if request_code == 202:
            task_url = request_result_json.get("@odata.id")
            ibmc.log_info("Delete RAID configuration task url is: %s" % str(task_url))
        else:
            log_msg = "Failed to delete LD: %s, The error code is: %s, The error info is: %s" % \
                      (storage_volume_id, str(request_code), str(request_result_json))
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
    except Exception as e:
        log_msg = "Failed to delete LD: %s, The error info is: %s" % (storage_volume_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

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
            ibmc.log_error("Get task status exception, The error info is: %s, continue..." % str(e))
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
              ibmc                    (class):    Class that contains basic information about iBMC
              raid_info               (list):     User-set RAID information
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/11/9 18:04
    """
    ibmc.log_info("Start modify RAID configuration...")

    # Initialize return information
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

    # Before create RAID configuration, make sure x86 is power on state
    check_power_state(ibmc)

    # Obtain all RAID storage ID
    all_raid_storage_id = get_all_storage_id(ibmc)

    # Verify User-set RAID controller id and volume id
    for volume in volumes:
        # Obtain User-set RAID controller ID
        storage_id = volume.get("storage_id")
        if not storage_id:
            log_msg = "The RAID storage id cannot be empty"
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret
        if storage_id not in all_raid_storage_id:
            log_msg = "The RAID storage id: %s does not exist" % storage_id
            set_result(ibmc.log_error, log_msg, False, ret)
            return ret

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

    for volume in volumes:
        # Initialize payload
        payload = {}
        oem = {}

        # Obtain User-set RAID controller ID
        storage_id = volume.get("storage_id")
        volume_id = volume.get("volume_id")
        volume_name = volume.get("volume_name")
        df_read_policy = volume.get("df_read_policy")
        df_write_policy = volume.get("df_write_policy")
        df_cache_policy = volume.get("df_cache_policy")
        boot_enable = volume.get("boot_enable")
        bgi_enable = volume.get("bgi_enable")
        access_policy = volume.get("access_policy")
        ssd_cache_enable = volume.get("ssd_cache_enable")
        disk_cache_policy = volume.get("disk_cache_policy")

        if volume_name is not None:
            try:
                if len(volume_name) > MAX_VOLUME_NAME_LEN:
                    log_msg = "Invalid length of the volume name, the maximum length is %s" % str(MAX_VOLUME_NAME_LEN)
                    set_result(ibmc.log_error, log_msg, False, ret)
                    return ret
            except Exception as e:
                ibmc.log_error('The volume name is illegal! The error info is: %s \n' % str(e))
                raise ValueError('The volume name is illegal! The error info is: %s' % str(e))
            oem["VolumeName"] = volume_name

        if df_read_policy:
            df_read_policy = DF_READ_POLICY.get(str(df_read_policy).lower())
            if df_read_policy in DF_READ_POLICY.values():
                oem["DefaultReadPolicy"] = df_read_policy
            else:
                log_msg = 'The default read policy is incorrect, It should be "NoReadAhead", "ReadAhead"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if df_write_policy:
            df_write_policy = DF_WRITE_POLICY.get(str(df_write_policy).lower())
            if df_write_policy in DF_WRITE_POLICY.values():
                oem["DefaultWritePolicy"] = df_write_policy
            else:
                log_msg = 'The default write policy is incorrect, It should be "WriteThrough", ' \
                          '"WriteBackWithBBU", "WriteBack"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if df_cache_policy:
            df_cache_policy = DF_CACHE_POLICY.get(str(df_cache_policy).lower())
            if df_cache_policy in DF_CACHE_POLICY.values():
                oem["DefaultCachePolicy"] = df_cache_policy
            else:
                log_msg = 'The default cache policy is incorrect, It should be "CachedIO", "DirectIO"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if boot_enable is not None:
            if boot_enable is True:
                oem["BootEnable"] = True
            else:
                log_msg = 'The boot enabled is incorrect, It can only be true'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if bgi_enable is not None:
            if bgi_enable is True:
                oem["BGIEnable"] = True
            elif bgi_enable is False:
                oem["BGIEnable"] = False
            else:
                log_msg = 'The bgi enabled is incorrect, It should be True or False'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if access_policy:
            access_policy = ACCESS_POLICY.get(str(access_policy).lower())
            if access_policy in ACCESS_POLICY.values():
                oem["AccessPolicy"] = access_policy
            else:
                log_msg = 'The access policy is incorrect, It should be "ReadWrite", "ReadOnly", "Blocked"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if ssd_cache_enable is not None:
            if ssd_cache_enable is True:
                oem["SSDCachingEnable"] = True
            elif ssd_cache_enable is False:
                oem["SSDCachingEnable"] = False
            else:
                log_msg = 'The ssd cache enabled is incorrect, It should be True or False'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        if disk_cache_policy:
            disk_cache_policy = DISK_CACHE_POLICY.get(str(disk_cache_policy).lower())
            if disk_cache_policy in DISK_CACHE_POLICY.values():
                oem["DriveCachePolicy"] = disk_cache_policy
            else:
                log_msg = 'The disk cache policy is incorrect, It should be "Unchanged", "Enabled", "Disabled"'
                set_result(ibmc.log_error, log_msg, False, ret)
                return ret

        payload["Oem"] = {"Huawei": oem}

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
        log_msg = "Failed to modify RAID configuration, The result is: %s" % str(result_list)
        set_result(ibmc.log_error, log_msg, False, ret)
        return ret

    log_msg = "Modify RAID configuration successful!, The result is: %s" % str(result_list)
    set_result(ibmc.log_info, log_msg, True, ret)
    return ret


def modify_raid_request(ibmc, payload, storage_id, volume_id):
    """
    
    Function:
        Send modify RAID configuration request
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
              payload         (dict):    Request message body
              storage_id      (str):     RAID controller ID
              volume_id       (str):     Volume ID
    Returns:
        ret
    Raises:
        None
    Examples:
        None
    Author:
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
    headers = {'content-type': 'application/json', 'X-Auth-Token': token, 'If-Match': etag}

    storage_volume_id = storage_id + "/" + volume_id

    try:
        # Modify RAID configuration by PATCH method
        request_result = ibmc.request('PATCH', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code == 200:
            log_msg = "Modify RAID: %s configuration successful!" % storage_volume_id
            set_result(ibmc.log_info, log_msg, True, ret)
        else:
            log_msg = "Failed to modify RAID: %s, The error code is: %s, The error info is: %s." % \
                      (storage_volume_id, str(request_code), str(request_result.json()))
            set_result(ibmc.log_error, log_msg, False, ret)
    except Exception as e:
        log_msg = "Failed to modify RAID: %s, The error info is: %s." % (storage_volume_id, str(e))
        set_result(ibmc.log_error, log_msg, False, ret)
    return ret


def get_all_storage_url(ibmc):
    """

    Function:
        Get all RAID storage information
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
    Returns:
        all RAID storage url
    Raises:
        Get RAID storage resource info failed!
    Examples:
        None
    Author:
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
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get RAID storage resource info failed! The error code is: %s, "
                           "The error info is: %s \n" % (str(request_code), str(request_result.json())))
            raise Exception("Get RAID storage resource info failed! The error code is: %s, "
                            "The error info is: %s." % (str(request_code), str(request_result.json())))
        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error("Get RAID storage resource info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Get RAID storage resource info failed!")

    return request_result_json


def get_all_storage_id(ibmc):
    """

    Function:
        Get all RAID storage information
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
    Returns:
        all RAID storage id, Example: [RAIDStorage0,RAIDStorage1]
    Raises:
        Get RAID storage resource info failed! or
        Get RAID storage id failed!
    Examples:
        None
    Author:
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
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get RAID storage resource info failed! The error code is: %s, "
                           "The error info is: %s \n" % (str(request_code), str(request_result.json())))
            raise Exception("Get RAID storage resource info failed! The error code is: %s, "
                            "The error info is: %s." % (str(request_code), str(request_result.json())))
    except Exception as e:
        ibmc.log_error("Get RAID storage resource info failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Get RAID storage resource info failed!")

    request_result_json = request_result.json()
    all_raid_storage_id = []
    try:
        for members in request_result_json.get("Members"):
            raid_storage_url = members["@odata.id"]
            all_raid_storage_id.append(str(raid_storage_url).split("/")[-1])
    except Exception as e:
        ibmc.log_error("Get RAID storage id failed! The error info is: %s \n" % str(e))
        raise Exception("Get RAID storage id failed! The error info is: %s" % str(e))

    return all_raid_storage_id


def get_all_volume_id(ibmc, storage_id):
    """

    Function:
        Get all volume of a RAID controller
    Args:
              ibmc                    (class):    Class that contains basic information about iBMC
              storage_id              (class):    RAID controller id
    Returns:
        all volume id, example: [LogicalDrive0,LogicalDrive1]
    Raises:
        Send get volume request failed! or
        Get all volume id failed!
    Examples:
        None
    Author:
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
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain the error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get all volume info failed! The error code is: %s, The error info is: %s \n" %
                           (str(request_code), str(request_result.json())))
            raise requests.exceptions.RequestException(
                "Get all volume info failed! failed! The error code is: %s, The error info is: %s." % (
                    str(request_code), str(request_result.json())))
    except Exception as e:
        ibmc.log_error("Send get volume request failed! The error info is: %s \n" % str(e))
        raise Exception("Get all volume info failed! The error info is: %s" % str(e))

    # Save all volume
    all_volume_id = []
    request_result_json = request_result.json()
    try:
        for members in request_result_json.get("Members"):
            volume_url = members["@odata.id"]
            all_volume_id.append(str(volume_url).split("/")[-1])
    except Exception as e:
        ibmc.log_error("Get all volume id failed! The error info is: %s \n" % str(e))
        raise Exception("Get all volume id failed! The error info is: %s" % str(e))
    return all_volume_id


def get_task_status(ibmc, task_url):
    """

    Function:
        Get task status
    Args:
              ibmc            (class):   Class that contains basic information about iBMC
              task_url        (class):   URL of task
    Returns:
        Task result
    Raises:
        Get task resource failed!
    Examples:
        None
    Author:
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
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
    except Exception as e:
        ibmc.log_error("Send get task result request failed! The error info is: %s \n" % str(e))
        raise requests.exceptions.RequestException("Get task resource failed! The error info is: %s" % str(e))

    try:
        if request_result.status_code == 200:
            request_result_json = request_result.json()
            task_status = request_result_json[u'TaskState']
            if task_status == "Running":
                result.append("Running")
            elif task_status == "Completed" and request_result_json['Messages']['Message'].find("successfully") != -1:
                result.append("Successful")
                result.append(request_result_json['Messages']['MessageArgs'][0])
            else:
                result.append(task_status)
                result.append(request_result_json['Messages']['Message'])
        else:
            result.append("Failed")
            result.append("Unknown error!")
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
              ibmc            (class):   Class that contains basic information about iBMC
    Returns:
        None
    Raises:
        Get RAID configuration resource info failed! or
        The server has been powered off, Retry after powering on the server
    Examples:
        None
    Author:
    Date: 2019/11/5 21:52
    """
    systems_source = ibmc.get_systems_resource()
    try:
        power_state = systems_source.get("PowerState")
    except Exception as e:
        ibmc.log_error("Get system power state failed! The error info is: %s \n" % str(e))
        raise Exception("Get RAID configuration resource info failed! The error info is: %s" % str(e))

    if power_state != "On":
        ibmc.log_error("The server has been powered off, Retry after powering on the server")
        raise Exception("The server has been powered off, Retry after powering on the server")
