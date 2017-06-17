#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auth: Wz

"""
采集服务器，虚拟机信息
"""

import os
import sys
import socket
import platform
import re
import commands
import json
import math
import struct
import fcntl
import urllib2
import random
import time
import datetime

DOMAIN = 'xxx'
API_URL = 'http://%s/p.gif' % DOMAIN
DOWNLOAD_URL = 'http://%s/download' % DOMAIN
CRONTAB = '0 */1 * * * curl -s %s/collect_info.py|/usr/bin/python > /tmp/asset_collect.log 2>&1' % DOWNLOAD_URL

ROOT_DIR = '/opt/shield/asset/'
TMP_DIR = os.path.join(ROOT_DIR, 'tmp')

# 操作系统类型
OS_UNKNOWN = 0
OS_CENTOS = 1
OS_UBUNTU = 2
OS_DEBIAN = 3
OS_REDHAT = 4

# 设备类型
TYPE_SERVER = 0
TYPE_VM = 1


def valid_mac(mac):
    """判断MAC地址是否合法"""
    try:
        pattern = r"^([0-9a-fA-F]{2}:){5}([0-9a-fA-F]{2}){1}$"
        if re.match(pattern, mac.strip().upper()):
            return True
        else:
            return False
    except Exception, e:
        return False


def valid_ip(ip):
    """判断IP地址是否合法"""
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
    except Exception, e:
        return False


def get_os():
    """
    获取操作系统类型以及版本号
    return (OS_CENTOS, 'CentOS 6.2')

    python -c "import platform; print platform.dist()"
    ('centos', '6.2', 'Final')
    ('Ubuntu', '12.04', 'precise')
    ('debian', '6.0.7', '')
    ('centos', '7.2.1511', 'Core')
    ('centos', '7.0.1406', 'Core')
    ('centos', '6.6', 'Final')
    ('redhat', '6.5', 'Santiago')

    python -c "import platform; print platform.linux_distribution()"
    ('CentOS', '5.5', 'Final')
    ('CentOS', '6.2', 'Final')
    ('Ubuntu', '12.04', 'precise')
    ('debian', '6.0.7', '')
    ('debian', '7.1', '')
    ('CentOS', '6.6', 'Final')
    ('CentOS Linux', '7.2.1511', 'Core')
    ('CentOS Linux', '7.0.1406', 'Core')
    ('Red Hat Enterprise Linux Server', '6.5', 'Santiago')
    """

    # res = platform.dist() # centos 5.5将返回redhat 5.5
    res = platform.linux_distribution()

    # 获取操作系统版本号, 只保留x.x, 不足的全部显示
    version_list = res[1].split('.')

    if len(version_list) > 2:
        version = "%s.%s" % (version_list[0], version_list[1])
    else:
        version = res[1]

    if re.search('(?i)^centos', res[0]):
        return (OS_CENTOS, 'CentOS %s' % version)

    if re.search('(?i)^ubuntu', res[0]):
        return (OS_UBUNTU, 'Ubuntu %s' % version)

    if re.search('(?i)^debian', res[0]):
        return (OS_DEBIAN, 'Debian %s' % version)

    if re.search('(?i)^red\s?hat', res[0]):
        return (OS_REDHAT, 'RedHat %s' % version)

    return (OS_UNKNOWN, '')


def set_crontab(os_code):
    """设置定时任务"""
    if os_code in [OS_CENTOS, OS_REDHAT]:
        cron_file = '/var/spool/cron/root'
    elif os_code in [OS_UBUNTU, OS_DEBIAN]:
        cron_file = '/var/spool/cron/crontabs/root'
    else:
        return

    if os.path.exists(cron_file):
        commands.getoutput('''sed -i "/.*curl.*collect_info\.py/d" %s''' % cron_file)
    else:
        commands.getoutput('touch %s' % cron_file)
        commands.getoutput('chmod 600 %s' % cron_file)

    commands.getoutput('''echo "%s" >> %s''' % (CRONTAB, cron_file))
    return


def check_required_packets(os_code):
    """检查脚本执行所需命令"""
    packets = ['curl', 'wget', 'bc', 'dmidecode']

    if os_code in [OS_CENTOS, OS_REDHAT]:
        for packet in packets:
            check_cmd = "rpm -q %s > /dev/null 2>&1" % packet

            if os.system(check_cmd) != 0:
                os.system("yum install -y %s > /dev/null 2>&1" % packet)

                if os.system(check_cmd) != 0:
                    return False

    if os_code in [OS_UBUNTU, OS_DEBIAN]:
        for packet in packets:
            check_cmd = "dpkg -l %s > /dev/null 2>&1" % packet

            if os.system(check_cmd) != 0:
                os.system("apt-get install -y %s > /dev/null 2>&1" % packet)

                if os.system(check_cmd) != 0:
                    return False

    return True


def get_manufacturer():
    """获取设备制造商"""
    status, result = commands.getstatusoutput('dmidecode -s system-manufacturer|grep -v "^#"')

    if status != 0 or result in ['System manufacturer']:
        return ''

    if re.search('(?i)^dell', result):
        return 'Dell'

    if re.search('(?i)^ibm', result):
        return 'IBM'

    if re.search('(?i)^lenovo', result):
        return 'Lenovo'

    if re.search('(?i)^huawei', result):
        return 'Huawei'

    if re.search('(?i)^hp', result):
        return 'HP'

    if re.search('(?i)^inspur', result):
        return 'Inspur'

    return result.strip()


def get_model():
    """获取设备类型和型号"""
    status, result = commands.getstatusoutput('dmidecode -s system-product-name|grep -v "^#"')

    if status != 0 or result in ['Not Specified', 'System Product Name']:
        result = ''

    manufacturer = get_manufacturer()

    if re.search('(?i)kvm|vmware|Bochs|OpenStack|Virtual Machine', result) or re.search('(?i)QEMU', manufacturer):
        return (TYPE_VM, '')

    if not manufacturer or re.search('(?i)%s' % manufacturer, result):
        return (TYPE_SERVER, result.strip())
    else:
        return (TYPE_SERVER, ("%s %s" % (manufacturer, result)).strip())


def get_users():
    """获取系统所有可登录用户"""
    if not os.path.exists('/etc/passwd') or not os.path.exists('/etc/shadow'):
        return []

    status, result = commands.getstatusoutput("""grep -iE '/bin/bash|/bin/zsh|/bin/sh' /etc/passwd| awk -F ':' '{print $1}'|sort|awk '{printf $1"\t"}'""")
    if status != 0:
        return []

    users = []

    for user in result.split():
        if user in ['root']:
            continue

        if os.system('grep -q "^%s:\\\$" /etc/shadow' % user) == 0:
            users.append(user)

    return users


def get_cpu():
    model_name_list = []
    physical_id_list = []
    processor_list = []
    cpu_cores_list = []

    for line in open('/proc/cpuinfo').read().split('\n'):
        model_name = re.match(r'^model\s+name\s+:\s*(.*)', line)
        physical_id = re.match(r'^physical\s+id\s+:\s*(\d*)', line)
        processor = re.match(r'^processor\s+:\s*(\d*)', line)
        cpu_cores = re.match(r'^cpu\s+cores\s+:\s*(\d*)', line)

        if model_name and model_name.group(1) not in model_name_list:
            model_name_list.append(model_name.group(1))

        if physical_id and physical_id.group(1) not in physical_id_list:
            physical_id_list.append(physical_id.group(1))

        if processor:
            processor_list.append(processor.group(1))

        if cpu_cores and cpu_cores.group(1) not in cpu_cores_list:
            cpu_cores_list.append(cpu_cores.group(1))

    cpu = {
        'model': ' '.join(';'.join(model_name_list).split()),
        'phyCount': len(physical_id_list),
        'logicCount': len(processor_list),
        'coreCount': 0
    }

    if len(cpu_cores_list) == 1:
        cpu['coreCount'] = int(cpu_cores_list[0])

    return cpu


def get_mac(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])
    except Exception, e:
        return ''


def get_ip(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except Exception, e:
        return ''


def get_nic():
    """获取设备网卡信息，忽略没有MAC和IP的网卡"""
    nic = []

    result = commands.getoutput("""ifconfig|grep "^\w"|awk '{print $1}'|grep -Ev "^(lo|docker|virbr0|bridge|tap|tun)"|sed 's;:$;;g'|sort|awk '{printf $1"\t"}'""")

    for label in result.split():
        mac = get_mac(label)
        ip = get_ip(label)

        if valid_mac(mac) and valid_ip(ip):
            nic.append({'label': label, 'mac': mac.upper(), 'ip': ip})

    return nic


def get_mem():
    mem_dict = {}

    for i in commands.getoutput('dmidecode -t memory').split('Memory Device'):
        m = re.search(r'\s+Size:\s+(\d+)\s+(MB|GB)', i)

        if m:
            size = int(m.group(1))
            unit = m.group(2)

            if re.search('MB', unit):
                if size < 1024:
                    mem_unit = "%sM" % size
                else:
                    mem_unit = "%sG" % (size / 1024)
            elif re.search('GB', unit):
                mem_unit = "%sG" % size

            if mem_dict.has_key(mem_unit):
                mem_dict[mem_unit] += 1
            else:
                mem_dict[mem_unit] = 1

    mem = []
    for i in sorted(mem_dict.items(), key=lambda item: item[0]):
        mem.append({'label': i[0], 'count': i[1]})

    return mem


def format_disk(bytes):
    """格式化硬盘大小"""

    def m_round(x, y):
        unit = y * 10
        return math.floor(x * unit) / unit

    size_MB = int(bytes) / 1000 / 1000

    if size_MB < 950:
        return str(size_MB) + 'M'

    if size_MB < 1050:
        return '1G'

    size_GB = size_MB / 1000

    if size_GB < 10:
        return str(m_round(size_MB / 1000.0, 1)) + 'G'

    if size_GB < 290:
        return str(size_GB) + 'G'

    if size_GB < 310:
        return '300G'

    if size_GB < 900:
        return str(size_GB) + 'G'

    if size_GB < 1100:
        return '1T'

    if size_GB < 1900:
        return str(m_round(size_MB / 1000.0 / 1000.0, 1)) + 'T'

    if size_GB < 2100:
        return '2T'

    if size_GB < 3900:
        return str(m_round(size_MB / 1000.0 / 1000.0, 1)) + 'T'

    if size_GB < 4100:
        return '4T'

    if size_GB < 9900:
        return str(m_round(size_MB / 1000.0 / 1000.0, 1)) + 'T'

    if size_GB < 10100:
        return '10T'

    return str(size_MB / 1000 / 1000) + 'T'


def get_real_disk():
    real_dict = {}

    for i in commands.getoutput('fdisk -l 2> /dev/null').split('\n'):
        m = re.match(r'^Disk \/dev\/(s|h|d|v|memdiska|nvme).*,\s+(\d+)\s+bytes', i)

        if m:
            disk_unit = format_disk(int(m.group(2)))

            if real_dict.has_key(disk_unit):
                real_dict[disk_unit] += 1
            else:
                real_dict[disk_unit] = 1

    real = []
    for i in sorted(real_dict.items(), key=lambda item: item[0]):
        real.append({'label': i[0], 'count': i[1]})

    return real


def get_sn():
    status, result = commands.getstatusoutput('dmidecode -s system-serial-number|grep -v "^#"')
    if status != 0:
        return ''

    if result in ['Not Specified', 'System Serial Number']:
        return ''

    return result.strip()


def check_megacli(os_code):
    script_path = os.path.join(ROOT_DIR, 'megacli')

    if os.system('%s -v > /dev/null 2>&1' % script_path) == 0:
        return True

    if os_code in [OS_CENTOS, OS_REDHAT]:
        packet = os.path.join(TMP_DIR, 'megacli_rpm.tgz')
        packet_url = "%s/megacli_rpm.tgz" % DOWNLOAD_URL

        commands.getoutput('wget -q --no-check-certificate %s -O %s' % (packet_url, packet))
        commands.getoutput('tar -zxf %s -C %s' % (packet, TMP_DIR))
        commands.getoutput('rpm -ivh --replacefiles %s %s' % (os.path.join(TMP_DIR, 'Lib_Utils-1.00-09.noarch.rpm'), os.path.join(TMP_DIR, 'MegaCli-8.02.21-1.noarch.rpm')))

    if os_code in [OS_UBUNTU, OS_DEBIAN]:
        packet = os.path.join(TMP_DIR, 'megacli_deb.tgz')
        packet_url = "%s/megacli_deb.tgz" % DOWNLOAD_URL

        commands.getoutput('wget -q --no-check-certificate %s -O %s' % (packet_url, packet))
        commands.getoutput('tar -zxf %s -C %s' % (packet, TMP_DIR))
        commands.getoutput('dpkg -i %s' % os.path.join(TMP_DIR, 'lib-utils_1.00-10_all.deb'))
        commands.getoutput('dpkg -i %s' % os.path.join(TMP_DIR, 'megacli_8.02.21-2_all.deb'))

    if os.path.exists(script_path):
        os.remove(script_path)

    if int(commands.getoutput('getconf LONG_BIT')) == 64:
        commands.getoutput('cp /opt/MegaRAID/MegaCli/MegaCli64 %s' % script_path)
    else:
        commands.getoutput('cp /opt/MegaRAID/MegaCli/MegaCli %s' % script_path)

    commands.getoutput('chmod +x %s' % script_path)

    if os.system('%s -v > /dev/null 2>&1' % script_path) == 0:
        return True
    else:
        return False


def check_lsiutil():
    script_path = os.path.join(ROOT_DIR, 'lsiutil')

    if os.system('%s -h > /dev/null 2>&1' % script_path) == 0:
        return True

    packet = os.path.join(TMP_DIR, 'lsiutil.tgz')
    packet_url = "%s/lsiutil.tgz" % DOWNLOAD_URL

    commands.getoutput('wget -q --no-check-certificate %s -O %s' % (packet_url, packet))
    commands.getoutput('tar -zxf %s -C %s' % (packet, TMP_DIR))

    if os.path.exists(script_path):
        os.remove(script_path)

    if int(commands.getoutput('getconf LONG_BIT')) == 64:
        commands.getoutput('cp %s %s' % (os.path.join(TMP_DIR, 'lsiutil.x86_64'), script_path))
    else:
        commands.getoutput('cp %s %s' % (os.path.join(TMP_DIR, 'lsiutil'), script_path))

    commands.getoutput('chmod +x %s' % script_path)

    if os.system('%s -h > /dev/null 2>&1' % script_path) == 0:
        return True
    else:
        return False


def get_megacli():
    raid = []
    script_path = os.path.join(ROOT_DIR, 'megacli')

    result = commands.getoutput('''%s -LDInfo -Lall -aALL|grep -E "(^RAID Level)|(^Size)|(^Number Of Drives)|(^Span Depth)"''' % script_path)

    RAID_Level_list = []
    Size_list = []
    Number_Of_Drives_list = []
    Span_Depth_list = []

    for i in result.split('\n'):
        if re.match('^RAID Level', i):
            if re.search('Primary-0.*Secondary-0', i):
                RAID_Level = 'RAID0'
            elif re.search('Primary-1.*Secondary-0', i):
                RAID_Level = 'RAID1'
            elif re.search('Primary-5.*Secondary-0', i):
                RAID_Level = 'RAID5'
            elif re.search('Primary-1.*Secondary-3', i):
                RAID_Level = 'RAID10'
            else:
                RAID_Level = 'RAIDX'  # 未知RAID等级

            RAID_Level_list.append(RAID_Level)

        if re.match('^Size', i):
            d = i.split(':')[1].strip().split()

            if re.search('(?i)MB', d[1]):
                total = format_disk(float(d[0]) * 1024 * 1024)
            elif re.search('(?i)GB', d[1]):
                total = format_disk(float(d[0]) * 1024 * 1024 * 1024)
            elif re.search('(?i)TB', d[1]):
                total = format_disk(float(d[0]) * 1024 * 1024 * 1024 * 1024)
            else:
                total = str(float(d[0])) + d[1]

            Size_list.append(total)

        if re.match('^Number Of Drives', i):
            Number_Of_Drives_list.append(int(i.split(':')[1]))

        if re.match('^Span Depth', i):
            Span_Depth_list.append(int(i.split(':')[1]))

    for i in zip(RAID_Level_list, Size_list, Number_Of_Drives_list, Span_Depth_list):
        if i[0] == 'RAID1' and i[3] == 2:
            label = 'RAID10'
        else:
            label = i[0]

        raid.append({
            'label': label,
            'count': i[2] * i[3],
            'total': i[1]
        })

    return raid


def get_lsiutil():
    raid = []
    script_path = os.path.join(ROOT_DIR, 'lsiutil')

    result = commands.getoutput('%s -p1 -a 21,1,0,0|grep -i "Volume Size"' % script_path)

    for i in result.split('\n'):
        m = re.search('Volume Size\s+(.*)', i)

        if m:
            d = m.group(1).split(',')
            d0 = d[0].strip().split()

            if re.search('(?i)MB', d0[1]):
                total = format_disk(int(d0[0]) * 1024 * 1024)
            elif re.search('(?i)GB', d0[1]):
                total = format_disk(int(d0[0]) * 1024 * 1024 * 1024)
            elif re.search('(?i)TB', d0[1]):
                total = format_disk(int(d0[0]) * 1024 * 1024 * 1024 * 1024)
            else:
                total = str(float(d0[0])) + d0[1]

            count = int(d[1].strip().split()[0])

            if count == 2:
                label = 'RAID1'
            else:
                label = 'RAIDX'

            raid.append({'label': label, 'count': count, 'total': total})

    return raid


def get_partition_info():
    def get_fs_info(path):
        hddinfo = os.statvfs(path)

        total = float(hddinfo.f_blocks)
        used = float(hddinfo.f_blocks - hddinfo.f_bavail)
        used_percent = round(used / total * 100, 2)

        return used_percent

    data = []

    with open('/proc/mounts', 'r') as f:
        for mount in f.readlines():
            try:
                if mount.startswith('/dev/') and not mount.startswith('/dev/mapper/docker'):
                    mount_list = mount.split()

                    if mount_list[2] == 'iso9660' or mount_list[1].startswith('/var/lib/docker') or mount_list[1].startswith('/tmp/SECUPD') or mount_list[1].endswith('docker/devicemapper'):
                        continue

                    target = mount_list[1]
                    used_percent = get_fs_info(target)

                    data.append({
                        'name': target,
                        'percent': used_percent,
                    })
            except Exception as e:
                pass

    return data


def push_data(args):
    def send(args):
        try:
            headers = {'Content-Type': 'application/json'}
            request = urllib2.Request(url=API_URL, headers=headers, data=json.dumps(args, separators=(',', ':')))
            response = urllib2.urlopen(request, timeout=5)
            response.close()

            return (True, 'ok')
        except Exception, e:
            return (False, str(e))

    for i in range(5):
        status, result = send(args)

        print "i=%s, status=%s, result=%s" % (i, status, result)

        if status:
            break

        interval = random.randint(1, 5) * 60 + i * 30

        time.sleep(interval)


def main():
    # 加载系统路径
    os.environ["PATH"] = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:' + os.environ["PATH"]

    if not os.path.exists(TMP_DIR):
        os.makedirs(TMP_DIR)

    os_code, OS = get_os()

    if os_code == OS_UNKNOWN:
        print "脚本不支持该操作系统, 只支持centos, ubuntu, debian, redhat"
        sys.exit(1)

    if not check_required_packets(os_code):
        print "安装脚本必须命令失败"
        sys.exit(1)

    device_type, Model = get_model()

    args = {
        'type': device_type,
        'Model': Model,
        'OS': OS,
        'hostname': socket.gethostname(),
        'SN': '',
        'CPU': get_cpu(),
        'MEM': get_mem(),
        'Disk': {'real': get_real_disk(), 'raid': []},
        'nic': get_nic(),
        'users': get_users(),

        # 虚拟机所需参数
        'HostIP': '',

        # 其他参数(目前尚未使用)
        'uuid': commands.getoutput('dmidecode -s system-uuid|grep -v "^#"'),
        'manufacturer': commands.getoutput('dmidecode -s system-manufacturer|grep -v "^#"'),
        'product_name': commands.getoutput('dmidecode -s system-product-name|grep -v "^#"'),
        'time_point': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),

        # 获取硬盘分区使用率
        'partition': get_partition_info(),
    }

    if device_type != TYPE_VM:
        args['SN'] = get_sn()

        # 判断是否为dell服务器,目前的RAID信息只支持DELL服务器
        if re.search('(?i)^dell', Model):
            if not check_megacli(os_code):
                print "[error]: <DELL RAID>megacli install failed!"
                sys.exit(1)

            if not check_lsiutil():
                print "[error]: <DELL RAID>lsiutil install failed!"
                sys.exit(1)

            args['Disk']['raid'].extend(get_megacli())
            args['Disk']['raid'].extend(get_lsiutil())

    print json.dumps(args, indent=4)

    push_data(args)

    set_crontab(os_code)


if __name__ == '__main__':
    main()
