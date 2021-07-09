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
import subprocess
import sys
import time
import shutil

from ibmc_ansible.utils import IBMC_EXCU_PATH

print('Start installing Huawei ibmc_ansible module')

try:
    import ansible
    from ansible.module_utils.six.moves import input
except ImportError as e:
    print("Ansible is not installed.")
    sys.exit(1)

try:
    import requests
except ImportError as e:
    print("You must install the python requests module. Otherwise, the iBMC cannot be connected!")

ansible_installed_path = ansible.__path__[0]

ibmc_lib_path = os.path.join(ansible_installed_path, "modules")

if os.path.exists(os.path.join(ibmc_lib_path, 'ibmc')):
    print("The ibmc_ansible module already exists, Do you want to upgrade it? (y/n)")
    choice = input()
    if choice in ['y', 'Y']:
        ret = subprocess.call(["cp", "-r", "./ibmc_ansible/ibmc", ibmc_lib_path], shell=False)
        if ret != 0:
            print("Failed to copy ibmc module!")
            sys.exit(1)
    else:
        print("Cancel installation ibmc_ansible module!")
        sys.exit(1)
else:
    ret = subprocess.call(["cp", "-r", "./ibmc_ansible/ibmc", ibmc_lib_path], shell=False)
    if ret != 0:
        print("Failed to copy ibmc_ansible/ibmc module!")
        sys.exit(1)

ibmc_utils_path = os.path.join(ansible_installed_path, "../")

ibmc_utils_path = os.path.join(ibmc_utils_path, "ibmc_ansible")
date_str = time.strftime("%Y%m%d%H%M%S", time.localtime())
yml_bak = ("%s_%s") % (IBMC_EXCU_PATH, date_str)
if os.path.exists(IBMC_EXCU_PATH):
    print("Backup the %s to %s" % (IBMC_EXCU_PATH, yml_bak))
    ret = subprocess.call(["cp", "-r", IBMC_EXCU_PATH, yml_bak], shell=False)
    if ret != 0:
        print("Failed to backup the %s to %s!" % (IBMC_EXCU_PATH, yml_bak))
else:
    ret = subprocess.call(["mkdir", "-p", IBMC_EXCU_PATH], shell=False)
    if ret != 0:
        print("Failed to mkdir %s" % IBMC_EXCU_PATH)
        print("Installation failed!")
        sys.exit(1)

ret = subprocess.call(["cp", "-r", "./examples", IBMC_EXCU_PATH], shell=False)
if ret != 0:
    print("Failed to copy yml to %s" % IBMC_EXCU_PATH)

ret = subprocess.call(["cp", "./ssl.cfg", IBMC_EXCU_PATH], shell=False)
if ret != 0:
    print("Failed to copyssl.cfg to %s" % IBMC_EXCU_PATH)

if not os.path.exists(ibmc_utils_path):
    ret = subprocess.call(["mkdir", "-p", ibmc_utils_path], shell=False)
    if ret != 0:
        print("Failed to mkdir %s" % ibmc_utils_path)
        print("Installation failed!")
        sys.exit(1)

flag = False
for file_name in os.listdir('./ibmc_ansible/'):
    if file_name.endswith(".py"):
        flag = True
        file_path = os.path.join('./ibmc_ansible/', file_name)
        shutil.copy(file_path, ibmc_utils_path)
if not flag:
    print("Failed to copy ibmc_ansible utile files")
    print("Installation failed!")
    sys.exit(1)

ret = subprocess.call(["cp", "-rf", "./ibmc_ansible/ibmc_redfish_api", ibmc_utils_path], shell=False)
if ret != 0:
    print("Failed to copy ibmc redfish api")
    print("Installation failed!")
    sys.exit(1)

print('Installation Huawei ibmc_ansible module completed')
sys.exit(0)
