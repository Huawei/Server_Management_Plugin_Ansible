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

from ibmc_ansible.utils import IBMC_EXCU_PATH

print('start uninstalling Huawei ibmc_ansible module')
try:
    import ansible
    from ansible.module_utils.six.moves import input
except ImportError as e:
    print("Ansible is not installed.")
    sys.exit(1)

ansible_installed_path = ansible.__path__[0]
flag_remove_example = False
ibmc_lib_path = os.path.join(ansible_installed_path, "modules")
if os.path.exists(os.path.join(ibmc_lib_path, 'ibmc')):
    while True:
        print("do you want to keep the yml files?(y/n)")
        choice = input()
        if choice in ['y', 'Y']:
            break
        elif choice in ['n', 'N']:
            flag_remove_example = True
            break
        else:
            print("you have press the wrong key")
    ret = subprocess.call(["rm", "-rf", os.path.join(ibmc_lib_path, 'ibmc')], shell=False)
    if ret != 0:
        print("rm ibmc_ansible_module failed")

    ibmc_utils_path = os.path.join(ansible_installed_path, "../")
    ibmc_utils_path = os.path.join(ibmc_utils_path, "ibmc_ansible")

    ret = subprocess.call(["rm", "-rf", ibmc_utils_path], shell=False)
    if ret != 0:
        print("rm ibmc_ansible_refish api  failed")
    if flag_remove_example:
        ret = subprocess.call(["rm", "-rf", IBMC_EXCU_PATH], shell=False)
        if ret != 0:
            print("rm ibmc ansible yml failed")
    print("finish uninstalling ibmc_ansible modules")
    sys.exit(0)

else:
    print("can not find ibmc_ansible module !")
    sys.exit(1)
