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
import json

from ibmc_ansible.utils import write_result, write_result_csv
from ibmc_ansible.utils import IBMC_REPORT_PATH

VER_HEADER = ["ProductName", "Model", "Status", "SerialNumber", "AssetTag", "iBMCVersion", "BiosVersion", "CPLDVersion",
              "SPVersion"]
SUMMARY_HEADER = ["CPUCount", "CPUStatus", "MemoryGiB", "MemoryStatus", "DriveCount", "DriveStatus"]


def get_drives_info(ibmc, chassis_json):
    """
    Function:
        get drives info
    Args:
         ibmc:   IbmcBaseConnect Object
         chassis_json: chassis resource info
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2019/10/26
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
         ibmc:   IbmcBaseConnect Object
         systems_json: systems resource
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2019/10/26
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
         ibmc:   IbmcBaseConnect Object
         systems_json : system resource
    Returns:
        {"BiosVersion": "1.17", "SerialNumber": "42353423"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2019/10/26
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
    Date: 2019/11/23
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


def get_cpld_info(ibmc):
    """
    Function:
        get fan info
    Args:
         ibmc:   IbmcBaseConnect Object
         chassis_json: chassis json data
    Returns:
        cpld info
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2020/10/10
    """
    token = ibmc.get_token()
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}
    payload = {}
    cpld_info = {}
    try:
        uri = "https://%s%s" % (ibmc.ip, "/redfish/v1/UpdateService/FirmwareInventory/MainBoardCPLD")
        r = ibmc.request('GET', resource=uri, headers=headers, data=payload, tmout=30)
        result = r.status_code
        if result == 200:
            cpld_info = r.json()
        else:
            ibmc.log_error(
                "Failed to get mainboard cpld info, the error code is: %d, error info is: %s" % (result, str(r.json())))
    except Exception as e:
        ibmc.log_error("Failed to get mainboard cpld info, the error info is: %s" % str(e))

    return cpld_info


def get_server_info(ibmc, systems_r, manager_r, chassis_r):
    """
    Function:
        get server info
    Args:
         ibmc: IbmcBaseConnect Object
         systems_r:  Systems resource info
         manager_r:  Manager resource info
         chassis_r:  Chassis resource info
    Returns:
        {"iBMCVersion": "6.50", "BiosVersion": "1.17", "CPLDVersion": "1.04(U108)"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2020/10/9
    """
    js = {}
    summary = {}

    try:
        # get iBMC, BIOS, CPLD version
        js['iBMCVersion'] = manager_r.get('FirmwareVersion')
        js['BiosVersion'] = systems_r.get('BiosVersion')
        cpld_info = get_cpld_info(ibmc)
        js['CPLDVersion'] = cpld_info.get('Version')

        # get oem info
        systems_oem = systems_r['Oem']['Huawei']
        chassis_oem = chassis_r['Oem']['Huawei']

        # get server basic info
        js['ProductName'] = systems_oem.get('ProductName')
        js['Name'] = systems_r.get('Name')
        js['UUID'] = systems_r.get('UUID')
        js['AssetTag'] = systems_r.get('AssetTag')
        js['Manufacturer'] = systems_r.get('Manufacturer')
        js['Model'] = systems_r.get('Model')
        js['HostName'] = systems_r.get('HostName')
        js['PartNumber'] = systems_r.get('PartNumber')
        js['SerialNumber'] = systems_r.get('SerialNumber')
        js['PowerState'] = systems_r.get('PowerState')
        js['Status'] = systems_r['Status']['Health']

        # get summary info
        summary['ProcessorSummary'] = systems_r.get('ProcessorSummary')
        summary['MemorySummary'] = systems_r.get('MemorySummary')
        summary['StorageSummary'] = systems_oem.get('StorageSummary')
        summary['NetworkAdaptersSummary'] = chassis_oem.get('NetworkAdaptersSummary')
        summary['PowerSupplySummary'] = chassis_oem.get('PowerSupplySummary')
        summary['DriveSummary'] = chassis_oem.get('DriveSummary')
        fan_info = get_fan_info(ibmc, chassis_r)
        if 'FanSummary' in fan_info['Oem']['Huawei'].keys():
            summary['FanSummary'] = fan_info['Oem']['Huawei']['FanSummary']
        else:
            summary['FanSummary'] = None
        js['Summary'] = summary

    except Exception as e:
        ibmc.log_error("Failed to get server info, the error info is: %s" % str(e))

    return js


def get_sp_info(ibmc):
    """
    Function:
        get sp info
    Args:
         ibmc:   IbmcBaseConnect Object
    Returns:
        {"result": True, "msg": "Get sp info successful!"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2020/12/09
    """

    # Get the return result of the redfish interface
    request_result_json = get_sp_info_request(ibmc)

    if request_result_json == {}:
        return None

    sp_json = {
        "Id": request_result_json.get("Id"),
        "Name": request_result_json.get("Name"),
        "SPStartEnabled": request_result_json.get("SPStartEnabled"),
        "SysRestartDelaySeconds": request_result_json.get("SysRestartDelaySeconds"),
        "SPTimeout": request_result_json.get("SPTimeout"),
        "SPFinished": request_result_json.get("SPFinished"),
        "Version": request_result_json.get("Version")
    }
    return sp_json


def get_sp_info_request(ibmc):
    """

    Function:
        Get the return result of the redfish interface
    Args:
        ibmc (class): Class that contains basic information about iBMC
    Returns:
        SP request info
    Raises:
        Get sp resource info failed!
    Examples:
        None
    Author:
    Date: 2020/09/12
    """
    # Obtain the token information of the iBMC
    token = ibmc.bmc_token

    # URL of the sp service
    url = ibmc.manager_uri + "/SPService"

    # Initialize headers
    headers = {'content-type': 'application/json', 'X-Auth-Token': token}

    # Initialize payload
    payload = {}

    request_result_json = {}

    try:
        # Obtain the sp resource information through the GET method
        request_result = ibmc.request('GET', resource=url, headers=headers, data=payload, tmout=30)
        # Obtain error code
        request_code = request_result.status_code
        if request_code != 200:
            ibmc.log_error("Get sp resource info failed! The error code is: %s, "
                           "The error info is: %s \n" % (str(request_code), str(request_result.json())))
        else:
            request_result_json = request_result.json()
    except Exception as e:
        ibmc.log_error("Get sp resource info failed! The error info is: %s \n" % str(e))

    return request_result_json


def get_basic_info(ibmc, csv_format=False):
    """
    Args:
         ibmc:         IbmcBaseConnect Object
         csv_format (bool):  Whether to write the result to a CSV file
    Returns:
        {"result": True, "msg": "Get basic info successful!"}
    Raises:
        Exception
    Examples:
        None
    Author:
    Date: 2020/10/12
    """

    # Initialize return information
    ret = {'result': True, 'msg': ''}

    ibmc.log_info("Start get basic info...")
    try:
        systems_json = ibmc.get_systems_resource()
        chassis_json = ibmc.get_chassis_resource()
        manager_json = ibmc.get_manager_resource()
        # get server info
        result = get_server_info(ibmc, systems_json, manager_json, chassis_json)
        # get cpu info
        result['CPUInfo'] = get_cpu_info(ibmc, systems_json)
        # get drive info
        result['DriveInfo'] = get_drives_info(ibmc, chassis_json)
        # get memory info
        result['MemoryInfo'] = get_mem_info(ibmc, systems_json)
        # get sp info
        sp_info = get_sp_info(ibmc)
        if sp_info is not None:
            result['SPInfo'] = sp_info

    except Exception as e:
        ibmc.log_error("Get basic info exception! %s" % str(e))
        ret['result'] = False
        ret['msg'] = "Get basic info exception! %s" % str(e)
        return ret

    if csv_format is True:
        # get version info
        result_csv = []
        for title in VER_HEADER:
            if title != "SPVersion":
                result_csv.append(result.get(title))
            else:
                if "SPInfo" in result.keys():
                    result_csv.append(json.dumps(result["SPInfo"].get("Version")))
                else:
                    result_csv.append("")

        # get cpu, memory, drive info
        cpu_cut = cpu_status = mem_gib = mem_status = drive_cut = drive_status = None
        try:
            summary = result["Summary"]
            cpu_cut = summary["ProcessorSummary"]["Count"]
            cpu_status = summary["ProcessorSummary"]["Status"]["HealthRollup"]
            mem_gib = summary["MemorySummary"]["TotalSystemMemoryGiB"]
            mem_status = summary["MemorySummary"]["Status"]["HealthRollup"]
            drive_cut = summary["DriveSummary"]["Count"]
            drive_status = summary["DriveSummary"]["Status"]["HealthRollup"]
        except Exception as e:
            ibmc.log_error("Failed to get server summary info, the error info is: %s" % str(e))
        summary_seq = [cpu_cut, cpu_status, mem_gib, mem_status, drive_cut, drive_status]

        result_csv.extend(summary_seq)
        VER_HEADER.extend(SUMMARY_HEADER)
        file_name = os.path.join(IBMC_REPORT_PATH, "basic_info", "%s_BasicInfo.csv" % str(ibmc.ip))
        # write the result to csv file
        write_result_csv(ibmc, file_name, VER_HEADER, result_csv)
    else:
        file_name = os.path.join(IBMC_REPORT_PATH, "basic_info", "%s_BasicInfo.json" % str(ibmc.ip))
        # write the result to json file
        write_result(ibmc, file_name, result)

    ret = {'result': True, 'msg': 'Get basic info successful! For more detail information, '
                                  'please refer the report log: %s' % file_name}

    return ret
