#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

IBMC_REPORT_PATH = "/var/log/ansible/ibmc/report"
IBMC_LOG_PATH = "/var/log/ansible/ibmc/log"
IBMC_EXCU_PATH = "/home/ibmc_ansible"
MSG_FORMAT = "%s -- %s"

import json
import logging
import logging.handlers as handlers
import os
import re
import subprocess

import ConfigParser


def set_result(log_function, msg, result, ret):
    """

    Function:
         set result
    Args:
              log_function              (function):
              result       (bool):
              msg                  (str):
              ret               (dic):
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 2019/10/9 20:30
    """
    log_function(msg)
    ret['result'] = result
    ret['msg'] = msg


def ansible_ibmc_run_module(function_callback, ansible_module, log, report):
    """

    Function:
         write report _
    Args:
              function_callback              (function):   module function
              ansible_module       (class):
              log                  (class):
              report               (class):
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 2019/10/9 20:30
    """
    try:
        ret = function_callback(ansible_module)
        if ret['result'] is True:
            report.info(MSG_FORMAT % (str(ansible_module.params.get("ibmc_ip")), ret['msg']))
            ansible_module.exit_json(msg=ret['msg'])
        else:
            report.error(MSG_FORMAT % (str(ansible_module.params.get("ibmc_ip")), ret['msg']))
            ansible_module.fail_json(msg=ret['msg'])
    except Exception as e:
        log.error(MSG_FORMAT % (str(ansible_module.params.get("ibmc_ip")), str(e)))
        report.error(MSG_FORMAT % (str(ansible_module.params.get("ibmc_ip")), str(e)))
        ansible_module.fail_json(msg=str(e))


def ansible_get_loger(log_file, report_file, logger_name):
    """
    Args:
            logFile            (str):
            reportFile         (str):
            loggerName         (str):
    Returns:
        (log ,report)
    Raises:
        None
    Examples:
        None
    Author: xwh
    Date: 10/19/2019
    """
    LOG_FILE = log_file
    REPORT_FILE = report_file

    log_hander = handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024, backupCount=100)
    fmt = logging.Formatter("[%(asctime)s %(levelname)s ]- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    log_hander.setFormatter(fmt)
    log = logging.getLogger(logger_name)
    log.addHandler(log_hander)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s %(levelname)s ] - %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    report_hander = handlers.RotatingFileHandler(REPORT_FILE, maxBytes=1024 * 1024, backupCount=100)
    report_hander.setFormatter(fmt)
    report = logging.getLogger(logger_name + "report")
    report.addHandler(report_hander)
    report.setLevel(logging.INFO)
    return log, report


def write_result(ibmc, result_file, result):
    """

    Function:
        Write the result to a file
    Args:
              ibmc              (class):   Class that contains basic information about iBMC
              result_file       (str):     result file
              result            (json):    result data
    Returns:
        None
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/9 20:30
    """
    json_file = None
    try:
        # Create a path if the path does not exist
        result_path = os.path.dirname(result_file)
        if not os.path.exists(result_path):
            subprocess.call("mkdir -p %s" % result_path, shell=True)
        # Write the results to the file as an overlay
        json_file = open(result_file, "w")
        if json_file and result:
            json.dump(result, json_file, indent=4)
    except IOError as e:
        ibmc.log_error("failed to write result to %s, The error info is: %s" % (result_file, str(e)))
        ibmc.report_error("failed to write result to %s" % result_file)
        raise IOError("Failed to write result to %s, The error info is: %s" % (result_file, str(e)))
    finally:
        if json_file is not None:
            json_file.close()


def validate_ipv4(ip_str):
    """

    Function:
        Verify IPv4 address
    Args:
              ip_str            (str):   IPv4 address
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 19:39
    """
    if ip_str:
        ip_list = ip_str.split(".")
        if len(ip_list) != 4:
            return False
        try:
            for ip in ip_list:
                ip_int = int(ip)
                if ip_int < 0 or ip_int > 255:
                    return False
        except ValueError:
            return False
    return True


def validate_ipv6(ip_str):
    """

    Function:
        Verify IPv6 address
    Args:
              ip_str            (str):   IPv6 address
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 19:56
    """
    if not ip_str:
        return True

    # Normal IPv6 format
    hex_re = re.compile(r'^:{0,1}([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}:{0,1}$')
    # IPv4-compatible IPv6 format
    dotted_quad_re = re.compile(r'^:{0,1}([0-9a-fA-F]{0,4}:){2,6}(\d{1,3}\.){3}\d{1,3}$')

    if hex_re.match(ip_str):
        if ':::' in ip_str:
            return False
        if '::' not in ip_str:
            halves = ip_str.split(':')
            return len(halves) == 8 and halves[0] != '' and halves[-1] != ''
        halves = ip_str.split('::')
        if len(halves) != 2:
            return False
        if halves[0] != '' and halves[0][0] == ':':
            return False
        if halves[-1] != '' and halves[-1][-1] == ':':
            return False
        return True

    if dotted_quad_re.match(ip_str):
        if ':::' in ip_str:
            return False
        if '::' not in ip_str:
            halves = ip_str.split(':')
            return len(halves) == 7 and halves[0] != ''
        halves = ip_str.split('::')
        if len(halves) > 2:
            return False
        hex_list = ip_str.split(':')
        quads = hex_list[-1].split('.')
        for q in quads:
            if int(q) > 255 or int(q) < 0:
                return False
        return True
    return False


def validata_ipv4_in_gateway(ip, gateway, subnet_mask):
    """

    Function:
        Determine if IPv4 Address, Gateway, and Netmask match
    Args:
              ip            (str):   IPv4 address
              gateway       (str):   IPv4 gateway
              subnet_mask   (str):   IPv4 subnet_mask
    Returns:
        True or False
    Raises:
        None
    Examples:
        None
    Author:
    Date: 2019/10/8 20:14
    """
    if ip and gateway and subnet_mask:
        ip_list = ip.split(".")
        gateway_list = gateway.split(".")
        subnet_mask_list = subnet_mask.split(".")
        try:
            for i in range(4):
                if int(ip_list[i]) & int(subnet_mask_list[i]) != int(gateway_list[i]) & int(subnet_mask_list[i]):
                    return False
        except ValueError:
            return False
    return True


def read_ssl_verify(log):
    """
    Function:
        read_ssl_verify
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 11/12/2019
    """

    try:
        cfg = ConfigParser.ConfigParser()
        cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
        cfg.read(cfg_path)
        verify = cfg.get("ssl", "verify")
        if verify is True or verify == "True":
            return True
        elif verify is False or verify == "False":
            return False
        else:
            return verify
    except Exception as e:
        log.info("read ssl_cfg exception : %s" % str(e))
        return True


def read_ssl_force_tls(log):
    """
    Function:
        read_ssl_force_tls
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 24/12/2019
    """

    try:
        cfg = ConfigParser.ConfigParser()
        cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
        cfg.read(cfg_path)
        verify = cfg.get("ssl", "force_tls1_2")
        if verify is True or verify == "True":
            return True
        elif verify is False or verify == "False":
            return False
        else:
            return True
    except Exception as e:
        log.info("read ssl_cfg exception : %s" % str(e))
        return True


def set_ssl_cfg(verify, force_tls1_2, log):
    """
    Function:
        set ssl cfg
    Args:
        verify str
    Returns:
       None
    Raises:
       Exception
    Examples:
       None
    Author:
    Date: 11/12/2019
    """
    cfg_path = os.path.join(IBMC_EXCU_PATH, "ssl.cfg")
    try:
        with open(cfg_path, "r+") as file:
            file.truncate()
            file.seek(0)
            file.write("[ssl]\nverify = %s\nforce_tls1_2 = %s" % (str(verify), str(force_tls1_2)))
            log.info("set ssl_cfg sucessful")
            return True
    except Exception as e:
        log.error("set ssl_cfg failed, exception is : %s" % str(e))
    return False
