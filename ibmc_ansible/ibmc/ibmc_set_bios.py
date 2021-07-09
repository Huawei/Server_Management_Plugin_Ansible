#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 Huawei Technologies Co., Ltd. All rights reserved.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License v3.0+

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License v3.0+ for more detail


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: ibmc_set_bios

short_description: Set bios info

version_added: "2.5.0"

description:
    - "Modifying bios resource properties"

options:
  ibmc_ip:
    required: true
    default: None
    description:
      - iBMC IP address
  ibmc_user:
    required: true
    default: None
    description:
      - iBMC user name used for authentication
  ibmc_pswd:
    required: true
    default: None
    description:
      - iBMC user password used for authentication
  Immediately:
    required: false
    default: False
    description:
      - Whether to restart the system immediately for the configuration to take effect.
  bios_attribute:
    required: true
    default: None
    description:
      - User-specified BIOS configuration attributes.
  bios_attribute/QuickBoot:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quick boot mode
  bios_attribute/QuietBoot:
    required: false
    default: Disabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot mode
  bios_attribute/PXEBootToLanUEFI:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/PXEBootToLanLegacy:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/BootTypeOrder0:
    required: false
    default: HardDiskDrive
    choices:
      - HardDiskDrive
      - DVDROMDrive
      - PXE
      - Others
    description:
      - Enable or disable quiet boot
  bios_attribute/BootTypeOrder1:
    required: false
    default: DVDROMDrive
    choices:
      - HardDiskDrive
      - DVDROMDrive
      - PXE
      - Others
    description:
      - Enable or disable quiet boot
  bios_attribute/BootTypeOrder2:
    required: false
    default: PXE
    choices:
      - HardDiskDrive
      - DVDROMDrive
      - PXE
      - Others
    description:
      - Enable or disable quiet boot
  bios_attribute/BootTypeOrder3:
    required: false
    default: DVDROMDrive
    choices:
      - HardDiskDrive
      - DVDROMDrive
      - PXE
      - Others
    description:
      - Enable or disable quiet boot
  bios_attribute/CustomPowerPolicy:
    required: false
    default: Custom
    choices:
      - Efficiency
      - Performance
      - Custom
      - LoadBalance
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorHyperThreadingDisable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorEISTEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/PowerSaving:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/PStateDomain:
    required: false
    default: Enabled
    choices:
      - All
      - One
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorC1eEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/C6Enable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Auto
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/NumaEn:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/PCIeSRIOVSupport:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/VTdSupport:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/InterruptRemap:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/CoherencySupport:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/ATS:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/PassThroughDMA:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/BMCWDTEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/OSWDTEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/CREnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/GlobalBaudRate:
    required: false
    default: Enabled
    choices:
      - Rate115200
      - Rate57600
      - Rate38400
      - Rate19200
      - Rate9600
      - Rate4800
      - Rate2400
      - Rate1200
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorFlexibleRatioOverrideEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorHWPMEnable:
    required: false
    default: Enabled
    choices:
      - NativeMode
      - OutofBandMode
      - NativeModewithNoLegacySupport
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/TStateEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/EnableXE:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/MLCStreamerPrefetcherEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/MLCSpatialPrefetcherEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/MonitorMwaitEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/DCUStreamerPrefetcherEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/DCUIPPrefetcherEnable:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/ProcessorX2APIC:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
  bios_attribute/BootPState:
    required: false
    default: Enabled
    choices:
      - MaxEfficient
      - MaxPerformance
      - SetbyIntelNodeManager
    description:
      - Enable or disable quiet boot
  bios_attribute/QpiLinkSpeed:
    required: false
    default: Enabled
    choices:
      - Speed9.6GB/s
      - Speed10.4GB/s
      - Auto
      - UsePerLinkSetting
    description:
      - Enable or disable quiet boot
  bios_attribute/KtiLinkL0pEn:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
      - Auto
    description:
      - Enable or disable quiet boot
  bios_attribute/KtiLinkL1En:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
      - Auto
    description:
      - Enable or disable quiet boot
  bios_attribute/DDRFreqLimit:
    required: false
    default: Enabled
    choices:
      - Freq1866
      - Freq2133
      - Freq2400
      - Freq2666
      - OvrClk2933
      - Auto
    description:
      - Enable or disable quiet boot
  bios_attribute/PatrolScrub:
    required: false
    default: Enabled
    choices:
      - Enabled
      - Disabled
    description:
      - Enable or disable quiet boot
"""

EXAMPLES = """
 - name: set ibmc bios
    ibmc_set_bios :
      ibmc_ip: "{{ ibmc_ip }}"
      ibmc_user: "{{ ibmc_user }}"
      ibmc_pswd: "{{ ibmc_pswd }}"
      Immediately: False
      bios_attribute:
          QuickBoot: Disabled
          QuietBoot: Enabled
"""

RETURNS = """
    {"result": True, "msg": "Set BIOS configuration resource info successfully."}
"""

from ansible.module_utils.basic import AnsibleModule

from ibmc_ansible.ibmc_redfish_api.redfish_base import IbmcBaseConnect
from ibmc_ansible.ibmc_redfish_api.api_manage_bios import set_bios
from ibmc_ansible.ibmc_logger import log, report
from ibmc_ansible.utils import ansible_ibmc_run_module, SERVERTYPE, is_support_server


def ibmc_set_bios_module(module):
    """
    Function:
        Set BIOS resource attributes
    Args:
        module : information from yml
    Returns:
        ret : Task result
            "result": True or False
            "msg": description for success or failure
    Raises:
        None
    Date: 2021/2/22
    """
    with IbmcBaseConnect(module.params, log, report) as ibmc:
        ret = is_support_server(ibmc, SERVERTYPE)
        if ret['result']:
            ret = set_bios(ibmc, module.params["bios_attribute"], module.params["Immediately"])
    return ret


def main():
    # Use AnsibleModule to read yml files and convert it to dict
    module = AnsibleModule(
        argument_spec={
            "ibmc_ip": {"required": True, "type": 'str'},
            "ibmc_user": {"required": True, "type": 'str'},
            "ibmc_pswd": {"required": True, "type": 'str', "no_log": True},
            "Immediately": {"required": False, "type": 'bool'},
            "bios_attribute": {"required": True, "type": 'dict'}
        },
        supports_check_mode=False)

    ansible_ibmc_run_module(ibmc_set_bios_module, module, log, report)


if __name__ == '__main__':
    main()
