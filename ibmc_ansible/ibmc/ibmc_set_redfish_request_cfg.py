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
module: ibmc_set_redfish_request_cfg
short_description: set request config
version_added: "2.5.0"
description:
    - Set request config
options:
    verify:
        required: true
        default: None
        description:
            - the requests module verify server certify or not
        choices: [ True, False ]
    cetify:
        required: false
        default:
        description:
            - file path of the certify
    force_tls1_2:
        required: false
        default:
        description:
            - force to use tls1.2
        choices: [ True, False ]
    ciphers:
        required: false
        default:
        description:
            - Security cipher suite
'''

EXAMPLES = r'''
- name: set request config
  ibmc_set_redfish_request_cfg:
    verify: True
    certify:
    force_tls1_2: True
    ciphers:
'''

RETURNS = r'''
    "msg": "set verify sucessed"
'''

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_logger import report
from ibmc_ansible.ibmc_logger import log
from ibmc_ansible.utils import set_ssl_cfg
from ibmc_ansible.utils import ansible_ibmc_run_module
from ibmc_ansible.utils import set_result


def ibmc_set_request(module):
    """
    Function:
        Set SNMP trap resource properties
    Args:
              module       (class):

    Returns:
        {"result": False, "msg": 'not run set snmp trap yet'}
    Raises:
        None
    Examples:

    Author:
    Date: 2019/12/12 17:33
    """
    ret = {}
    if module.params.get("verify") is False:
        verify = False
    elif module.params.get("verify") is None or module.params.get("verify") == "":
        verify = True
    else:
        if module.params.get("verify") is True and module.params.get("certify"):
            verify = module.params.get("certify")
        else:
            verify = True
    ciphers = module.params.get("ciphers")
    if module.params.get("force_tls1_2") is False:
        force_tls1_2 = False
    else:
        force_tls1_2 = True

    r = set_ssl_cfg(verify, force_tls1_2, ciphers, log)
    if r:
        log_msg = "set verify sucessed"
        set_result(log.info, log_msg, True, ret)
    else:
        log_msg = "set verify failed"
        set_result(log.error, log_msg, False, ret)
    return ret


def main():
    module = AnsibleModule(
        argument_spec={
            "verify": {"required": True, "type": 'bool'},
            "certify": {"required": False, "type": 'str'},
            "force_tls1_2": {"required": False, "type": 'bool'},
            "ciphers": {"required": False, "type": 'str'},

        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_request, module, log, report)


if __name__ == '__main__':
    main()
