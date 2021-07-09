#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019-2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ibmc_ansible_show_version
short_description: Show Huawei iBMC ansible modules version
version_added: "2.5.0"
description:
    - Show Huawei iBMC ansible modules version
'''

EXAMPLES = r'''
- name: show Huawei iBMC ansible modules version
  ibmc_ansible_show_version:
'''

RETURNS = r'''
    "msg": Huawei iBMC ansible modules version is 2.0.6
'''

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec={},
        supports_check_mode=False)
    module.exit_json(msg="Huawei iBMC ansible modules version is 2.0.6")


if __name__ == '__main__':
    main()
