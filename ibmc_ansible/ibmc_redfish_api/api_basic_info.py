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
from ibmc_ansible.utils import write_result
from ibmc_ansible.utils import IBMC_REPORT_PATH


def get_drives_info(ibmc, chassis_json):
    """
    Function:
        get drives info
    Args:
         ibmc (str):   IbmcBaseConnect Object
         chassis_json: chassis resource info
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423", }
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 10/26/2019
    """
    drive_info = {}
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    list_json = []

    try:
        drivers = chassis_json['Links']['Drives']
        ibmc.log_info("Get dirver info, drivers total:%d" % len(drivers))
        if len(drivers) == 0:
            ibmc.log_info("There is haven't any driver.")
            return drive_info
        else:
            # get driver info one by one
            for each_members in drivers:
                uri = "https://%s%s" % (ibmc.ip, each_members['@odata.id'])
                r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
                result = r.status_code
                if result == 200:
                    each_json = r.json()
                    # delete no means info
                    if '@odata.context' in each_json.keys():
                        del each_json['@odata.context']
                    if 'Actions' in each_json.keys():
                        del each_json['Actions']
                    if '@odata.id' in each_json.keys():
                        del each_json['@odata.id']
                    list_json.append(each_json)
                else:
                    ibmc.log_error("Get %s failed! the error code is:%d" % (uri, result))

        drive_info = list_json
    except Exception as e:
        ibmc.log_error("Get drivers info failed:%s" % str(e))
    return drive_info


def get_mem_info(ibmc, systems_json):
    """
    Function:
        get memory info
    Args:
         ibmc (str):   IbmcBaseConnect Object
         systems_json: systems resource
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423", }
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 10/26/2019
    """
    memory_info = {}
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    list_json = []

    try:
        memory_uri = systems_json['Memory']['@odata.id']
        uri = "https://%s%s" % (ibmc.ip, memory_uri)
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 200:
            member_json = r.json()
            if "Members" not in list(member_json.keys()):
                return memory_info
            if len(member_json["Members"]) < 0:
                return memory_info

            # get memory info one by one
            ibmc.log_info("Get memory info, memory total: %s" % len(member_json[u"Members"]))
            for each_members in member_json[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
                result = r.status_code
                if result == 200:
                    each_json = r.json()
                    # delete no means info
                    if '@odata.id' in each_json.keys():
                        del each_json['@odata.id']
                    if '@odata.context' in each_json.keys():
                        del each_json['@odata.context']
                    list_json.append(each_json)
                else:
                    ibmc.log_error("get %s failed! the error code is:%d" % (uri, result))
            memory_info = list_json
        else:
            ibmc.log_error("Get memory info failed, the error number is:%d" % result)
    except Exception as e:
        ibmc.log_error("Get memory info failed:%s" % str(e))

    return memory_info


def get_cpu_info(ibmc, systems_json):
    """
    Function:
        get cpu info
    Args:
         ibmc (str):   IbmcBaseConnect Object
         systems_json : system resource
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423", }
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 10/26/2019
    """
    cpu_info = {}
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    list_json = []

    try:
        processors_uri = systems_json['Processors']['@odata.id']
        uri = "https://%s%s" % (ibmc.ip, processors_uri)
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 200:
            member_json = r.json()
            if "Members" not in list(member_json.keys()):
                ibmc.log_error("there are haven't members in member json!")
                return cpu_info
            if len(member_json["Members"]) < 0:
                ibmc.log_error("there are haven't any processor!")
                return cpu_info

            # get processor info one by one
            ibmc.log_info("Get processors info,processors total: %d" % len(member_json[u"Members"]))
            for each_members in member_json[u"Members"]:
                uri = "https://%s%s" % (ibmc.ip, each_members["@odata.id"])
                r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
                result = r.status_code
                if result == 200:
                    each_json = r.json()
                    # delete no means info
                    if '@odata.id' in each_json.keys():
                        del each_json['@odata.id']
                    if '@odata.context' in each_json.keys():
                        del each_json['@odata.context']
                    list_json.append(each_json)
                else:
                    ibmc.log_error("Get %s failed, the error number is:%d" % (uri, result))

            cpu_info = list_json
        else:
            ibmc.log_error("Get cpu info failed, the error number is:%d" % result)

    except Exception as e:
        ibmc.log_error("Get cpu info failed:%s" % str(e))

    return cpu_info


def get_fan_info(ibmc, chassis_json):
    """
    Function:
        get fan info
    Args:
         ibmc:   IbmcBaseConnect Object
         chassis_json: chassis json data
    Returns:
        {}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 11/23/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    fan_json = ""

    try:
        thermal_uri = chassis_json['Thermal']['@odata.id']
        uri = "https://%s%s" % (ibmc.ip, thermal_uri)
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 200:
            fan_json = r.json()
        else:
            ibmc.log_error("Get fan info failed, the error code is:%d, error info:%s" % (result, str(r.json())))

    except Exception as e:
        ibmc.log_error("Get fan info failed:%s" % str(e))

    return fan_json


def get_cpld_info(ibmc, chassis_json):
    """
    Function:
        get fan info
    Args:
         ibmc:   IbmcBaseConnect Object
         chassis_json: chassis json data
    Returns:
        {}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 11/23/2019
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    main_board_uri = ""
    cpld_json = ""
    board_json = ""
    try:
        board_uri = chassis_json['Oem']['Huawei']['Boards']['@odata.id']
        uri = "https://%s%s" % (ibmc.ip, board_uri)
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 200:
            board_json = r.json()
        else:
            ibmc.log_error("Get board info failed, the error code is:%d, error info:%s" % (result, str(r.json())))
        board_menbers = board_json['Members']
        for board in board_menbers:
            uri = board["@odata.id"]
            if "chassisMainboard" in uri.split("/")[-1]:
                main_board_uri = "https://%s%s" % (ibmc.ip, uri)
                break

        if main_board_uri != "":
            r = ibmc.request('GET', resource=main_board_uri, headers=headers, data=payload, tmout=30)
            result = r.status_code
            if result == 200:
                cpld_json = r.json()
            else:
                ibmc.log_error("Get cpld info failed, the error code is:%d, error info:%s" % (result, str(r.json())))
    except Exception as e:
        ibmc.log_error("Get cpld info failed:%s" % str(e))

    return cpld_json


def get_bmc_bios_info(ibmc, systems_r, manager_r, chassis_r):
    """
    Function:
        get bmc and bios info
    Args:
         ibmc (str):   IbmcBaseConnect Object
         systems_r: Systems resource info
         manager_r: Manager resource info
         chassis_r: Chassis resource info
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423", }
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 10/26/2019
    """
    js = {}
    summary = {}

    try:
        if 'FirmwareVersion' in manager_r.keys():
            js['FirmwareVersion'] = manager_r['FirmwareVersion']
        if 'BiosVersion' in systems_r.keys():
            js['BiosVersion'] = systems_r['BiosVersion']
        cpld_resoure = get_cpld_info(ibmc, chassis_r)
        if 'CPLDVersion' in cpld_resoure:
            js['CPLDVersion'] = cpld_resoure['CPLDVersion']
        if 'ProductName' in systems_r['Oem']['Huawei'].keys():
            js['ProductName'] = systems_r['Oem']['Huawei']['ProductName']
        if 'Name' in systems_r.keys():
            js['Name'] = systems_r['Name']
        if 'UUID' in systems_r.keys():
            js['UUID'] = systems_r['UUID']
        if 'AssetTag' in systems_r.keys():
            js['AssetTag'] = systems_r['AssetTag']
        if 'Manufacturer' in systems_r.keys():
            js['Manufacturer'] = systems_r['Manufacturer']
        if 'Model' in systems_r.keys():
            js['Model'] = systems_r['Model']
        if 'HostName' in systems_r.keys():
            js['HostName'] = systems_r['HostName']
        if 'PartNumber' in systems_r.keys():
            js['PartNumber'] = systems_r['PartNumber']
        if 'SerialNumber' in systems_r.keys():
            js['SerialNumber'] = systems_r['SerialNumber']
        if 'PowerState' in systems_r.keys():
            js['PowerState'] = systems_r['PowerState']
        if 'Status' in systems_r.keys():
            js['Status'] = systems_r['Status']['Health']

        if 'ProcessorSummary' in systems_r.keys():
            summary['ProcessorSummary'] = systems_r['ProcessorSummary']
        if 'MemorySummary' in systems_r.keys():
            summary['MemorySummary'] = systems_r['MemorySummary']
        if 'StorageSummary' in systems_r['Oem']['Huawei'].keys():
            summary['StorageSummary'] = systems_r['Oem']['Huawei']['StorageSummary']
        if 'NetworkAdaptersSummary' in chassis_r['Oem']['Huawei'].keys():
            summary['NetworkAdaptersSummary'] = chassis_r['Oem']['Huawei']['NetworkAdaptersSummary']
        if 'PowerSupplySummary' in chassis_r['Oem']['Huawei'].keys():
            summary['PowerSupplySummary'] = chassis_r['Oem']['Huawei']['PowerSupplySummary']
        if 'DriveSummary' in chassis_r['Oem']['Huawei'].keys():
            summary['DriveSummary'] = chassis_r['Oem']['Huawei']['DriveSummary']
        result = get_fan_info(ibmc, chassis_r)
        if 'FanSummary' in result['Oem']['Huawei'].keys():
            summary['FanSummary'] = result['Oem']['Huawei']['FanSummary']
        js['Summary'] = summary

    except Exception as e:
        ibmc.log_error("Get bmc and bios info failed:%s" % str(e))

    return js


def get_basic_info(ibmc):
    """
    Args:
         ibmc (str):   IbmcBaseConnect Object
    Returns:
        {'result':True,'msg': ""}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 10/26/2019
    """

    file_name = os.path.join(IBMC_REPORT_PATH, "basic_info", "%s_BasicInfo.json" % str(ibmc.ip))
    ret = {'result': True, 'msg': 'Get basic info successful! For more detail information, '
                                  'please refer the report log: %s' % file_name}
    result = {}

    ibmc.log_info("Get basic info start!")
    try:

        systems_json = ibmc.get_systems_resource()
        chassis_json = ibmc.get_chassis_resource()
        manager_json = ibmc.get_manager_resource()
        ibmc.log_info("Get bmc and bios info start!")
        result['bmc and bios info'] = get_bmc_bios_info(ibmc, systems_json, manager_json, chassis_json)
        ibmc.log_info("Get cpu info start!")
        result['cpu info'] = get_cpu_info(ibmc, systems_json)
        ibmc.log_info("Get drives info start!")
        result['drives info'] = get_drives_info(ibmc, chassis_json)
        ibmc.log_info("Get memory info start!")
        result['memory info'] = get_mem_info(ibmc, systems_json)

    except Exception as e:
        ibmc.log_error("Get basic info exception! %s" % str(e.message))
        ret['result'] = False
        ret['msg'] = "Get basic info exception! %s" % str(e.message)
        return ret

    # write the result to json file
    write_result(ibmc, file_name, result)

    return ret
