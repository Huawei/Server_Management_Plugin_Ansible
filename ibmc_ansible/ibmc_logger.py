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
import stat
from ibmc_ansible.utils import ansible_get_loger, IBMC_LOG_PATH, IBMC_REPORT_PATH, BASIC_PATH

if not os.path.exists(BASIC_PATH):
    os.makedirs(BASIC_PATH)
    os.chmod(BASIC_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

if not os.path.exists(IBMC_LOG_PATH):
    os.makedirs(IBMC_LOG_PATH)
    os.chmod(IBMC_LOG_PATH, stat.S_IRWXU)
if not os.path.exists(IBMC_REPORT_PATH):
    os.makedirs(IBMC_REPORT_PATH)
    os.chmod(IBMC_REPORT_PATH, stat.S_IRWXU)

LOG_FILE = "%s/ansibleibmc.log" % IBMC_LOG_PATH
REPORT_FILE = "%s/ansibleibmc.report" % IBMC_REPORT_PATH
log, report = ansible_get_loger(LOG_FILE, REPORT_FILE, "ansibleibmc")
