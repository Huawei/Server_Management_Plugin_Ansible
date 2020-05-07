#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2019 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: ibmc_ansible_show_version
short_description: "Huawei iBMC ansible modules 2.0.4"
version_added: "2.5.0"
description: "Huawei iBMC ansible modules 2.0.4"
"""

EXAMPLES = r"""
    - name:show ibmc version 
          ibmc_show_version:
         
"""

RETURNS = """
    Huawei iBMC ansible modules 2.0.4
"""

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec={},
        supports_check_mode=False)
    module.exit_json(msg="Huawei iBMC ansible modules 2.0.4")


if __name__ == '__main__':
    main()
