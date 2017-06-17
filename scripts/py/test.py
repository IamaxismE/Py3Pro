#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auth: Wz

import re
import uuid


def isValidIp(ip):
    # if re.match(r"^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$", ip): return True
    # return False
    try:
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(pattern, ip.strip()):
            ipaddr = ip.strip().split('.')
            for i in ipaddr:
                if int(i) < 0 or int(i) > 255:
                    return False
            return True
        else:
            return False
    except Exception as e:
        return False


def isValidMac(mac):
    if re.match(r"^\s*([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2}){1}\s*$", mac): return True
    # if re.match(r"^\s*([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}\s*$", mac): return True
    # if re.match(r'^[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}:[0-9,A-F]{2}$', mac): return True
    return False


def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    return mac


if __name__ == '__main__':
    print(isValidMac("6c:5F:F4:6B:3E:6F"))
    print(isValidIp("255.255.255.255"))
