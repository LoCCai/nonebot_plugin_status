# -*- coding: utf-8 -*-
'''
@name: 系统信息 / SystemInfo
@author: PurePeace
@time: 2020年8月17日
@version: 0.1
'''

from typing import List, Dict, Any

import os
import time
import psutil
import platform
import hashlib
import re
import sys


from cachelib import SimpleCache
cache = SimpleCache()


UNIX: bool = os.name == 'posix'
SYS: str = platform.system()


class CpuConstants:
    def __init__(self):
        '''
        初始化CPU常量（多平台）

        Returns
        -------
        self.

        '''
        self.WMI = None
        self.initialed: bool = False
        self.cpuList: list = [] # windows only

        self.cpuCount: int = 0 # 物理cpu数量
        self.cpuCore: int = 0 # cpu物理核心数
        self.cpuThreads: int = 0 # cpu逻辑核心数
        self.cpuName: str = '' # cpu型号

        self.Update(True)


    def Update(self, update: bool = False) -> None:
        '''
        更新cpu数据

        Returns
        -------
        None.

        '''
        if UNIX: self.GetCpuConstantsUnix(update)
        else: self.GetCpuConstantsWindows(update)

        self.initialed: bool = True


    @property
    def getDict(self) -> Dict[int, str]:
        '''
        以字典格式获取当前cpu常量

        Returns
        -------
        Dict[int, str]
            DESCRIPTION.

        '''
        if not self.initialed: self.Update()
        return {
            'cpu_count': self.cpuCount,
            'cpu_name': self.cpuName,
            'cpu_core': self.cpuCore,
            'cpu_threads': self.cpuThreads
        }


    def GetCpuConstantsUnix(self, update: bool = False) -> None:
        '''
        获取unix下的cpu信息

        Parameters
        ----------
        update : bool, optional
            DESCRIPTION. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        '''
        if update or not self.initialed:
            ids: list = re.findall("physical id.+", readFile('/proc/cpuinfo'))

            # 物理cpu个数
            self.cpuCount: int = len(set(ids))

            # cpu型号（名称）
            self.cpuName: str = self.getCpuTypeUnix()


            self.GetCpuConstantsBoth()


    def InitWmi(self) -> None:
        '''
        初始化wmi（for windows）

        Returns
        -------
        None
            DESCRIPTION.

        '''
        import wmi
        self.WMI = wmi.WMI()


    def GetCpuConstantsBoth(self, update: bool = False) -> None:
        '''
        获取多平台共用的cpu信息

        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        '''
        if update or not self.initialed:

            # cpu逻辑核心数
            self.cpuThreads: int = psutil.cpu_count()

            # cpu物理核心数
            self.cpuCore: int = psutil.cpu_count(logical=False)


    def GetCpuConstantsWindows(self, update: bool = False) -> None:
        '''
        获取windows平台的cpu信息

        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        '''
        if update or not self.initialed:

            # 初始化wmi
            if self.WMI == None: self.InitWmi()

            # cpu列表
            self.cpuList: list = self.WMI.Win32_Processor()

            # 物理cpu个数
            self.cpuCount: int = len(self.cpuList)

            # cpu型号（名称）
            self.cpuName: str = self.cpuList[0].Name


            self.GetCpuConstantsBoth()


    @staticmethod
    def getCpuTypeUnix() -> str:
        '''
        获取CPU型号（unix）

        Returns
        -------
        str
            CPU型号.

        '''
        cpuinfo: str = readFile('/proc/cpuinfo')
        rep: str = 'model\s+name\s+:\s+(.+)'
        tmp = re.search(rep,cpuinfo,re.I)
        cpuType: str = ''
        if tmp:
            cpuType: str = tmp.groups()[0]
        else:
            cpuinfo = ExecShellUnix('LANG="en_US.UTF-8" && lscpu')[0]
            rep = 'Model\s+name:\s+(.+)'
            tmp = re.search(rep,cpuinfo,re.I)
            if tmp: cpuType = tmp.groups()[0]
        return cpuType


def GetCpuInfo(interval: int = 1) -> Dict[str, Any]:
    '''
    获取CPU信息

    Parameters
    ----------
    interval : int, optional
        DESCRIPTION. The default is 1.

    Returns
    -------
    Dict[float, list, dict]
        DESCRIPTION.

    '''
    time.sleep(0.5)


    # cpu总使用率
    used: float = psutil.cpu_percent(interval)

    # 每个逻辑cpu使用率
    usedList: List[float] = psutil.cpu_percent(percpu=True)


    return {'used': used, 'used_list': usedList, **cpuConstants.getDict}


def readFile(filename: str) -> str:
    '''
    读取文件内容

    Parameters
    ----------
    filename : str
        文件名.

    Returns
    -------
    str
        文件内容.

    '''
    try:
        with open(filename, 'r', encoding='utf-8') as file: return file.read()
    except:
        pass

    return ''


def GetLoadAverage() -> dict:
    '''
    获取服务器负载状态（多平台）

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    try: c: list = os.getloadavg()
    except: c: list = [0,0,0]
    data: dict = {i: c[idx] for idx, i in enumerate(('one', 'five', 'fifteen'))}
    data['max'] = psutil.cpu_count() * 2
    data['limit'] = data['max']
    data['safe'] = data['max'] * 0.75
    return data


def GetMemInfo() -> dict:
    '''
    获取内存信息（多平台）

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    if UNIX: return GetMemInfoUnix()
    return GetMemInfoWindows()


def GetMemInfoUnix() -> Dict[str, int]:
    '''
    获取内存信息（unix）

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    mem = psutil.virtual_memory()
    memInfo: dict = {
        'memTotal': ToSizeInt(mem.total, 'MB'),
        'memFree': ToSizeInt(mem.free, 'MB'),
        'memBuffers': ToSizeInt(mem.buffers, 'MB'),
        'memCached': ToSizeInt(mem.cached, 'MB'),
    }
    memInfo['memRealUsed'] = \
        memInfo['memTotal'] - \
        memInfo['memFree'] - \
        memInfo['memBuffers'] - \
        memInfo['memCached']

    memInfo['memUsedPercent'] = memInfo['memRealUsed'] / memInfo['memTotal'] * 100

    return memInfo


def GetMemInfoWindows() -> dict:
    '''
    获取内存信息（windows）

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    mem = psutil.virtual_memory()
    memInfo: dict = {
        'memTotal': ToSizeInt(mem.total, 'MB'),
        'memFree': ToSizeInt(mem.free, 'MB'),
        'memRealUsed': ToSizeInt(mem.used, 'MB'),
        'memUsedPercent': mem.used / mem.total * 100
    }

    return memInfo


def ToSizeInt(byte: int, target: str) -> int:
    '''
    将字节大小转换为目标单位的大小

    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）
    target : str
        目标单位，str.

    Returns
    -------
    int
        转换为目标单位后的字节大小.

    '''
    return int(byte/1024**(('KB','MB','GB','TB').index(target) + 1))


def ToSizeString(byte: int) -> str:
    '''
    获取字节大小字符串

    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）.

    Returns
    -------
    str
        自动转换后的大小字符串，如：6.90 GB.

    '''
    units: tuple = ('b','KB','MB','GB','TB')
    re = lambda: '{:.2f} {}'.format(byte, u)
    for u in units:
        if byte < 1024: return re()
        byte /= 1024
    return re()


def GetDiskInfo() -> list:
    '''
    获取磁盘信息（多平台）

    Returns
    -------
    list
        列表.

    '''
    try:
        if UNIX: return GetDiskInfoUnix()
        return GetDiskInfoWindows()
    except Exception as err:
        print('获取磁盘信息异常（unix: {}）：'.format(UNIX), err)
        return []


def GetDiskInfoWindows() -> list:
    '''
    获取磁盘信息Windows

    Returns
    -------
    diskInfo : list
        列表.

    '''
    diskIo: list = psutil.disk_partitions()
    diskInfo: list = []
    for disk in diskIo:
        tmp: dict = {}
        try:
            tmp['path'] = disk.mountpoint.replace("\\","/")
            usage = psutil.disk_usage(disk.mountpoint)
            tmp['size'] = {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            }
            tmp['fstype'] = disk.fstype
            tmp['inodes'] = False
            diskInfo.append(tmp)
        except:
            pass
    return diskInfo


def GetDiskInfoUnix() -> list:
     '''
    获取硬盘分区信息（unix）

    Returns
    -------
    list
        DESCRIPTION.

    '''
     temp: list = (
         ExecShellUnix("df -h -P|grep '/'|grep -v tmpfs")[0]).split('\n')
     tempInodes: list = (
         ExecShellUnix("df -i -P|grep '/'|grep -v tmpfs")[0]).split('\n')
     diskInfo: list = []
     n: int = 0
     cuts: list = [
         '/mnt/cdrom',
         '/boot',
         '/boot/efi',
         '/dev',
         '/dev/shm',
         '/run/lock',
         '/run',
         '/run/shm',
         '/run/user'
     ]
     for tmp in temp:
         n += 1
         try:
             inodes: list = tempInodes[n-1].split()
             disk: list = tmp.split()
             if len(disk) < 5: continue
             if disk[1].find('M') != -1: continue
             if disk[1].find('K') != -1: continue
             if len(disk[5].split('/')) > 10: continue
             if disk[5] in cuts: continue
             if disk[5].find('docker') != -1: continue
             arr = {}
             arr['path'] = disk[5]
             tmp1 = [disk[1],disk[2],disk[3],disk[4]]
             arr['size'] = tmp1
             arr['inodes'] = [inodes[1],inodes[2],inodes[3],inodes[4]]
             diskInfo.append(arr)
         except Exception as ex:
             print('信息获取错误：', str(ex))
             continue
     return diskInfo



def md5(strings: str) -> str:
    '''
    生成md5

    Parameters
    ----------
    strings : TYPE
        要进行hash处理的字符串

    Returns
    -------
    str[32]
        hash后的字符串.

    '''

    m = hashlib.md5()
    m.update(strings.encode('utf-8'))
    return m.hexdigest()


def GetErrorInfo() -> str:
    '''
    获取traceback中的错误

    Returns
    -------
    str
        DESCRIPTION.

    '''
    import traceback
    errorMsg = traceback.format_exc()
    return errorMsg


def ExecShellUnix(cmdstring: str, shell=True):
    '''
    执行Shell命令（Unix）

    Parameters
    ----------
    cmdstring : str
        DESCRIPTION.
    shell : TYPE, optional
        DESCRIPTION. The default is True.

    Returns
    -------
    a : TYPE
        DESCRIPTION.
    e : TYPE
        DESCRIPTION.

    '''
    a: str = ''
    e: str = ''
    import subprocess,tempfile

    try:
        rx: str = md5(cmdstring)
        succ_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_succ',
            prefix = 'btex_' + rx ,
            dir = '/dev/shm'
        )
        err_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_err',
            prefix = 'btex_' + rx ,
            dir = '/dev/shm'
        )
        sub = subprocess.Popen(
            cmdstring,
            close_fds = True,
            shell = shell,
            bufsize = 128,
            stdout = succ_f,
            stderr = err_f
        )
        sub.wait()
        err_f.seek(0)
        succ_f.seek(0)
        a = succ_f.read()
        e = err_f.read()
        if not err_f.closed: err_f.close()
        if not succ_f.closed: succ_f.close()
    except Exception as err:
        print(err)
    try:
        if type(a) == bytes: a = a.decode('utf-8')
        if type(e) == bytes: e = e.decode('utf-8')
    except Exception as err:
        print(err)

    return a,e


def GetNetWork() -> dict:
    '''
    获取系统网络信息

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    networkIo: list = [0,0,0,0]
    cache_timeout: int = 86400
    try:
        networkIo = psutil.net_io_counters()[:4]
    except:
        pass

    otime = cache.get("otime")
    if not otime:
        otime = time.time()
        cache.set('up',networkIo[0],cache_timeout)
        cache.set('down',networkIo[1],cache_timeout)
        cache.set('otime',otime ,cache_timeout)

    ntime = time.time()
    networkInfo: dict = {'up': 0, 'down': 0}
    networkInfo['upTotal']   = networkIo[0]
    networkInfo['downTotal'] = networkIo[1]
    try:
        networkInfo['up'] = round(
            float(networkIo[0] - cache.get("up")) / 1024 / (ntime - otime),
            2
        )
        networkInfo['down'] = round(
            float(networkIo[1] - cache.get("down")) / 1024 / (ntime -  otime),
            2
        )
    except:
        pass

    networkInfo['downPackets'] = networkIo[3]
    networkInfo['upPackets'] = networkIo[2]

    cache.set('up',networkIo[0],cache_timeout)
    cache.set('down',networkIo[1],cache_timeout)
    cache.set('otime', time.time(),cache_timeout)

    return networkInfo


def GetSystemInfo() -> dict:
    systemInfo: dict = {}
    systemInfo['cpu'] = GetCpuInfo()
    systemInfo['load'] = GetLoadAverage()
    systemInfo['mem'] = GetMemInfo()
    systemInfo['disk'] = GetDiskInfo()

    return systemInfo



def GetIoReadWrite() -> Dict[str, int]:
    '''
    获取系统IO读写

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    ioDisk = psutil.disk_io_counters()
    ioTotal: dict = {}
    ioTotal['write'] = GetIoWrite(ioDisk.write_bytes)
    ioTotal['read'] = GetIoRead(ioDisk.read_bytes)
    return ioTotal


def GetIoWrite(ioWrite: int) -> int:
    '''
    获取IO写

    Parameters
    ----------
    ioWrite : TYPE
        DESCRIPTION.

    Returns
    -------
    int
        DESCRIPTION.

    '''
    diskWrite: int = 0
    oldWrite: int = cache.get('io_write')
    if not oldWrite:
        cache.set('io_write', ioWrite)
        return diskWrite;

    oldTime: float = cache.get('io_time')
    newTime: float = time.time()
    if not oldTime: oldTime = newTime
    ioEnd: int = (ioWrite - oldWrite)
    timeEnd: float = (time.time() - oldTime)
    if ioEnd > 0:
        if timeEnd < 1: timeEnd = 1
        diskWrite = ioEnd / timeEnd
    cache.set('io_write',ioWrite)
    cache.set('io_time',newTime)
    if diskWrite > 0: return int(diskWrite)
    return 0


def GetIoRead(ioRead):
    '''
    读取IO读

    Parameters
    ----------
    ioRead : TYPE
        DESCRIPTION.

    Returns
    -------
    TYPE
        DESCRIPTION.

    '''
    diskRead: int = 0
    oldRead: int = cache.get('io_read')
    if not oldRead:
        cache.set('io_read',ioRead)
        return diskRead;
    oldTime: float = cache.get('io_time')
    newTime: float = time.time()
    if not oldTime: oldTime = newTime
    ioEnd: int = (ioRead - oldRead)
    timeEnd: float = (time.time() - oldTime)
    if ioEnd > 0:
        if timeEnd < 1: timeEnd = 1;
        diskRead = ioEnd / timeEnd;
    cache.set('io_read', ioRead)
    if diskRead > 0: return int(diskRead)
    return 0


def GetRegValue(key: str, subkey: str, value: str) -> Any:
    '''
    获取系统注册表信息

    Parameters
    ----------
    key : str
        类型.
    subkey : str
        路径.
    value : str
        key.

    Returns
    -------
    value : Any
        DESCRIPTION.

    '''
    import winreg
    key = getattr(winreg, key)
    handle = winreg.OpenKey(key, subkey)
    (value, type) = winreg.QueryValueEx(handle, value)
    return value

def GetSys_Vers(tp) -> str:
    '''
    获取操作系统信息（多平台）
    tp=0    完整信息
    tp=1    系统名称
    tp=2    系统build
    tp=3    Python版本
    '''
    if UNIX: 
        try:
            version: str = readFile('/etc/redhat-release')
            if not version:
                version = readFile(
                    '/etc/issue'
                ).strip().split("\n")[0].replace('\\n','').replace('\l','').strip()
            else:
                version = version.replace(
                    'release ',''
                ).replace('Linux','').replace('(Core)','').strip()
            v = sys.version_info
            re_name=version
            re_build=""
            re_py='{}.{}.{}'.format(v.major, v.minor, v.micro)
            re: str = '{} (build {}) {} (Py{})'.format(
            re_name, re_build, bit, re_py)
        except Exception as err:
            print('获取系统版本失败，错误：', err)
            re: str = '未知系统版本.'
    try:
        import platform
        bit: str = 'x86';
        if 'PROGRAMFILES(X86)' in os.environ: bit = 'x64'

        def get(key: str):
            return GetRegValue(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key
            )
        re_name=get('ProductName')
        re_build=get('CurrentBuildNumber')
        re_py=platform.python_version()
        re: str = '{} (build {}) {} (Py{})'.format(
            re_name, re_build, bit, re_py)
    except Exception as ex:
        print('获取系统版本失败，错误：' + str(ex))
        re: str = '未知系统版本.'
    if tp==0:
        return re
    elif tp==1:
        return re_name
    elif tp==2:
        return re_build
    elif tp==3:
        return re_py

def GetSystemVersion() -> str:
    '''
    获取操作系统版本（多平台）

    Returns
    -------
    str
        DESCRIPTION.

    '''
    if UNIX: return GetSystemVersionUnix()
    return GetSystemVersionWindows()


def GetSystemVersionWindows() -> str:
    '''
    获取操作系统版本（windows）

    Returns
    -------
    str
        DESCRIPTION.

    '''
    try:
        import platform
        bit: str = 'x86';
        if 'PROGRAMFILES(X86)' in os.environ: bit = 'x64'

        def get(key: str):
            return GetRegValue(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key
            )

        osName = get('ProductName')
        build = get('CurrentBuildNumber')

        version: str = '{} (build {}) {} (Py{})'.format(
            osName, build, bit, platform.python_version())
        return version
    except Exception as ex:
        print('获取系统版本失败，错误：' + str(ex))
        return '未知系统版本.'


def GetSystemVersionUnix() -> str:
    '''
    获取系统版本（unix）

    Returns
    -------
    str
        系统版本.

    '''
    try:
        version: str = readFile('/etc/redhat-release')
        if not version:
            version = readFile(
                '/etc/issue'
            ).strip().split("\n")[0].replace('\\n','').replace('\l','').strip()
        else:
            version = version.replace(
                'release ',''
            ).replace('Linux','').replace('(Core)','').strip()
        v = sys.version_info
        return version + '(Py {}.{}.{})'.format(v.major, v.minor, v.micro)
    except Exception as err:
        print('获取系统版本失败，错误：', err)
        return '未知系统版本.'


def GetBootTime() -> dict:
    '''
    获取当前系统启动时间

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    bootTime: float = psutil.boot_time()
    return {
        'timestamp': bootTime,
        'runtime': time.time() - bootTime,
        'datetime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    }


def GetCpuConstants() -> dict:
    '''
    获取CPU常量信息

    Parameters
    ----------
    cpuConstants : CpuConstants
        DESCRIPTION.

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    return cpuConstants.getDict


def GetFullSystemData() -> dict:
    '''
    获取完全的系统信息

    Returns
    -------
    dict
        DESCRIPTION.

    '''
    systemData: dict = {
        **GetSystemInfo(),
        'network': { **GetNetWork() },
        'io': { **GetIoReadWrite() },
        'boot': { **GetBootTime() },
        'time': time.time()
    }
    return systemData

cpuConstants = CpuConstants()

def Time_Transf(seconds,tp):
    def _days(day):
        return "{} days ".format(day) if day > 1 else "{} day ".format(day)
    def _hours(hour):  
        return "{} hours ".format(hour) if hour > 1 else "{} hour ".format(hour)
    def _minutes(minute):
        return "{} minutes ".format(minute) if minute > 1 else "{} minute ".format(minute)
    def _seconds(second):  
        return "{} seconds".format(second) if second > 1 else "{} second".format(second)          
    days = seconds // (3600 * 24)
    hours = (seconds // 3600) % 24
    minutes = (seconds // 60) % 60
    seconds = seconds % 60
    if tp==0:
        if days > 0 :
            return _days(days)+_hours(hours)+_minutes(minutes)+_seconds(seconds)
        if hours > 0 :
            return _hours(hours)+_minutes(minutes)+_seconds(seconds)
        if minutes > 0 :
            return _minutes(minutes)+_seconds(seconds)
        return _seconds(seconds)
    elif tp==1:
        if days > 0 :
            residue_seconds=seconds+minutes*60
            residue_hours=residue_seconds/3600
            return _days(days)+_hours(round(hours+residue_hours,2))
        if hours > 0 :
            residue_seconds=seconds+minutes*60
            residue_hours=residue_seconds/3600
            return _hours(round(hours+residue_hours,2))
        if minutes > 0 :
            return _minutes(minutes)+_seconds(seconds)
        return _seconds(seconds)

def get_status():
    #获取系统信息
    text=GetFullSystemData()
    print(text)
    head_text="====qiqi-bot|status===="+"\n"
    Sys_Vers="系统版本="+GetSys_Vers(1)+"\n"
    Pyt_vers="Pytn版本="+"Py "+GetSys_Vers(3)+"\n"
    cpu_used="运行信息="+str(round(text['cpu']['used'],2))+"%   "+str(text['cpu']['cpu_count'])+" CPU"+" "+str(text['cpu']['cpu_core'])+" 核心"+" "+str(text['cpu']['cpu_threads'])+" 线程"+"\n"
    Mem_used="内存信息="+str(round(text['mem']['memUsedPercent'],2))+"% "+str(int(text['mem']['memFree']))+"MB 空"+" "+str(int(text['mem']['memRealUsed']))+"MB 用"+" "+str(int(text['mem']['memTotal']))+"MB 总"+"\n"
    cpu_name="CPU名称="+text['cpu']['cpu_name']+"\n"
    split_text="=======================\n"
    run_time="系统已运行 "+str(Time_Transf(text['boot']['runtime'],1))
    re=head_text+Sys_Vers+Pyt_vers+cpu_used+Mem_used+cpu_name+split_text+run_time
    return re

if __name__ == "__main__":
    print(get_status())