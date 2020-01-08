#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

from ibmc_ansible.utils import *

LOG_FILE = "%s/ansibleibmc.log" % IBMC_LOG_PATH
REPORT_FILE = "%s/ansibleibmc.report" % IBMC_REPORT_PATH
log, report = ansible_get_loger(LOG_FILE, REPORT_FILE, "ansibleibmc")
