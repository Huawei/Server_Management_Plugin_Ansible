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
import subprocess
import sys
import time

from ibmc_ansible.utils import IBMC_EXCU_PATH, IBMC_LOG_PATH, IBMC_REPORT_PATH

print('start installing Huawei ibmc_ansible module')



try:
    import ansible
    from ansible.module_utils.six.moves import input
except ImportError as e:
    print("Ansible is not installed.")
    sys.exit(1)

try:
    import requests
except ImportError as e:
    print("you have not install the requests module,you should intall it, otherwise you can not connect to IBMC")

ansible_installed_path = ansible.__path__[0]

ibmc_lib_path = os.path.join(ansible_installed_path, "modules")

if os.path.exists(os.path.join(ibmc_lib_path, 'ibmc')):
    print("the ibmc_ansible module is exists, do you want to upgrade it? (y/n)")
    choice = input()
    if choice in ['y', 'Y']:
        ret = subprocess.call("cp -r ./ibmc_ansible/ibmc %s" %
                              ibmc_lib_path, shell=True)
        if ret != 0:
            print("cp ibmc_ansible failed ")
            sys.exit(1)
    else:
        print("ibmc_ansible module install stop")
        sys.exit(1)
else:
    ret = 1
    ret = subprocess.call("cp -r ./ibmc_ansible/ibmc %s" %
                          ibmc_lib_path, shell=True)
    if ret != 0:
        print("copy ibmc_ansible/ibmc  failed !")
        sys.exit(1)

ibmc_utils_path = os.path.join(ansible_installed_path, "../")

ibmc_utils_path = os.path.join(ibmc_utils_path, "ibmc_ansible")
date_str = time.strftime("%Y%m%d%H%M%S", time.localtime())
yml_bak = ("%s_%s") % (IBMC_EXCU_PATH, date_str)
if os.path.exists(IBMC_EXCU_PATH):
    print("backup the %s to %s" % (IBMC_EXCU_PATH, yml_bak))
    ret = 1
    ret = subprocess.call("cp -r %s %s" %
                          (IBMC_EXCU_PATH, yml_bak), shell=True)
    if ret != 0:
        print("backup the %s to %s failed !" % (IBMC_EXCU_PATH, yml_bak))
else:
    ret = subprocess.call("mkdir -p %s" % IBMC_EXCU_PATH, shell=True)
    if ret != 0:
        print("mkdir %s failed " % IBMC_EXCU_PATH)
        print("install failed ")
        sys.exit(1)

ret = 1
ret = subprocess.call("cp -r ./examples %s" % IBMC_EXCU_PATH, shell=True)
if ret != 0:
    print("copy yml to %s failed " % IBMC_EXCU_PATH)

ret = 1
ret = subprocess.call("cp  ./uninstall.py %s" % IBMC_EXCU_PATH, shell=True)
if ret != 0:
    print("copy uninstall.py to %s failed " % IBMC_EXCU_PATH)

ret = 1
ret = subprocess.call("cp  ./ssl.cfg %s" % IBMC_EXCU_PATH, shell=True)
if ret != 0:
    print("copyssl.cfg to %s failed " % IBMC_EXCU_PATH)

if not os.path.exists(IBMC_LOG_PATH):
    ret = 1
    ret = subprocess.call("mkdir -p %s" % IBMC_LOG_PATH, shell=True)
    if ret != 0:
        print("mkdir %s failed " % IBMC_LOG_PATH)
        print("install failed ")
        sys.exit(1)

if not os.path.exists(IBMC_REPORT_PATH):
    ret = 1
    ret = subprocess.call("mkdir -p %s" % IBMC_REPORT_PATH, shell=True)
    if ret != 0:
        print("mkdir %s failed " % IBMC_REPORT_PATH)
        print("install failed ")
        sys.exit(1)

if not os.path.exists(ibmc_utils_path):
    ret = 1
    ret = subprocess.call("mkdir -p %s" % ibmc_utils_path, shell=True)
    if ret != 0:
        print("mkdir %s failed " % ibmc_utils_path)
        print("install failed ")
        sys.exit(1)

ret = 1
ret = subprocess.call("cp ./ibmc_ansible/*.py %s" %
                      ibmc_utils_path, shell=True)
if ret != 0:
    print("cp ibmc_ansible utile files failed ")
    print("install failed ")
    sys.exit(1)

ret = 1
ret = subprocess.call(
    "cp -rf  ./ibmc_ansible/ibmc_redfish_api %s" % ibmc_utils_path, shell=True)
if ret != 0:
    print("copy ibmc redfish api failed ")
    print("install failed ")
    sys.exit(1)

print('install Huawei ibmc_ansible module completely')
sys.exit(0)
