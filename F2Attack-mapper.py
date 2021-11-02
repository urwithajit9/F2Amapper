"""
Author: Ajit kumar
this script takes an exe as input and shows the API mapping as per malapi grouping.
malapi.io
Date: 2 Nov 2021

"""

#manually created list on Nov2 2021
## Feature: an automatic script to create below list with update on website
#crawl the website and update the List
enumeration =['CreateToolhelp32Snapshot', 'EnumDeviceDrivers', 'EnumProcesses', 'EnumProcessModules', 'EnumProcessModulesEx', 'FindFirstFileA', 'FindNextFileA', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetModuleBaseNameA', 'GetSystemDefaultLangId', 'GetVersionExA', 'GetWindowsDirectoryA', 'IsWoW64Process', 'Module32First', 'Module32Next', 'Process32First', 'Process32Next', 'ReadProcessMemory', 'Thread32First', 'Thread32Next', 'GetSystemDirectoryA', 'GetSystemTime', 'ReadFile', 'GetComputerNameA', 'VirtualQueryEx', 'GetProcessIdOfThread', 'GetProcessId', 'GetCurrentThread', 'GetCurrentThreadId', 'GetThreadId', 'GetThreadInformation', 'GetCurrentProcess', 'GetCurrentProcessId', 'SearchPathA', 'GetFileTime', 'GetFileAttributesA', 'LookupPrivilegeValueA', 'LookupAccountNameA', 'GetCurrentHwProfileA', 'GetUserNameA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegQueryInfoKeyA', 'RegQueryMultipleValuesA', 'RegQueryValueExA', 'NtQueryDirectoryFile', 'NtQueryInformationProcess', 'NtQuerySystemEnvironmentValueEx', 'EnumDesktopWindows', 'EnumWindows', 'NetShareEnum', 'NetShareGetInfo', 'NetShareCheck', 'GetAdaptersInfo', 'PathFileExistsA']
injection =['CreateFileMappingA', 'CreateProcessA', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'GetModuleHandleA', 'GetProcAddress', 'GetThreadContext', 'HeapCreate', 'LoadLibraryA', 'LoadLibraryExA', 'LocalAlloc', 'MapViewOfFile', 'MapViewOfFile2', 'MapViewOfFile3', 'MapViewOfFileEx', 'OpenThread', 'Process32First', 'Process32Next', 'QueueUserAPC', 'ReadProcessMemory', 'ResumeThread', 'SetProcessDEPPolicy', 'SetThreadContext', 'SuspendThread', 'Thread32First', 'Thread32Next', 'Toolhelp32ReadProcessMemory', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'VirtualAllocExNuma', 'VirtualAlloc2', 'VirtualAlloc2FromApp', 'VirtualAllocFromApp', 'VirtualProtectFromApp', 'CreateThread', 'WaitForSingleObject', 'OpenProcess', 'OpenFileMappingA', 'GetProcessHeap', 'GetProcessHeaps', 'HeapAlloc', 'HeapReAlloc', 'GlobalAlloc', 'AdjustTokenPrivileges', 'CreateProcessAsUserA', 'OpenProcessToken', 'CreateProcessWithTokenW', 'NtAdjustPrivilegesToken', 'NtAllocateVirtualMemory', 'NtContinue', 'NtCreateProcess', 'NtCreateProcessEx', 'NtCreateSection', 'NtCreateThread', 'NtCreateThreadEx', 'NtCreateUserProcess', 'NtDuplicateObject', 'NtMapViewOfSection', 'NtOpenProcess', 'NtOpenThread', 'NtProtectVirtualMemory', 'NtQueueApcThread', 'NtQueueApcThreadEx', 'NtQueueApcThreadEx2', 'NtReadVirtualMemory', 'NtResumeThread', 'NtUnmapViewOfSection', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'NtWriteVirtualMemory', 'RtlCreateHeap', 'LdrLoadDll', 'RtlMoveMemory', 'RtlCopyMemory', 'SetPropA', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx']
evasion =['CreateFileMappingA', 'DeleteFileA', 'GetModuleHandleA', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryExA', 'LoadResource', 'SetEnvironmentVariableA', 'SetFileTime', 'Sleep', 'WaitForSingleObject', 'SetFileAttributesA', 'SleepEx', 'NtDelayExecution', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'CreateWindowExA', 'RegisterHotKey', 'timeSetEvent', 'IcmpSendEcho', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx', 'SetWaitableTimer', 'CreateTimerQueueTimer', 'CreateWaitableTimer', 'SetWaitableTimer', 'SetTimer', 'Select']
spying =['AttachThreadInput', 'CallNextHookEx', 'GetAsyncKeyState', 'GetClipboardData', 'GetDC', 'GetDCEx', 'GetForegroundWindow', 'GetKeyboardState', 'GetKeyState', 'GetMessageA', 'GetRawInputData', 'GetWindowDC', 'MapVirtualKeyA', 'MapVirtualKeyExA', 'PeekMessageA', 'PostMessageA', 'PostThreadMessageA', 'RegisterHotKey', 'RegisterRawInputDevices', 'SendMessageA', 'SendMessageCallbackA', 'SendMessageTimeoutA', 'SendNotifyMessageA', 'SetWindowsHookExA', 'SetWinEventHook', 'UnhookWindowsHookEx', 'BitBlt', 'StretchBlt']
internet =['WinExec', 'FtpPutFileA', 'HttpOpenRequestA', 'HttpSendRequestA', 'HttpSendRequestExA', 'InternetCloseHandle', 'InternetOpenA', 'InternetOpenUrlA', 'InternetReadFile', 'InternetReadFileExA', 'InternetWriteFile', 'URLDownloadToFile', 'URLDownloadToCacheFile', 'URLOpenBlockingStream', 'URLOpenStream', 'Accept', 'Bind', 'Connect', 'Gethostbyname', 'Inet_addr', 'Recv', 'Send', 'WSAStartup', 'Gethostname', 'Socket', 'WSACleanup', 'Listen', 'ShellExecuteA', 'ShellExecuteExA', 'DnsQuery_A', 'DnsQueryEx']
anti_debugging =['CreateToolhelp32Snapshot', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetTickCount', 'OutputDebugStringA', 'CheckRemoteDebuggerPresent', 'Sleep', 'GetSystemTime', 'GetComputerNameA', 'SleepEx', 'IsDebuggerPresent', 'GetUserNameA', 'NtQueryInformationProcess', 'ExitWindowsEx', 'FindWindowA', 'FindWindowExA', 'GetTickCount64', 'QueryPerformanceFrequency', 'QueryPerformanceCounter']
ransomware =['CryptAcquireContextA', 'EncryptFileA', 'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey', 'CryptSetKeyParam', 'CryptGetHashParam', 'CryptSetKeyParam', 'CryptDestroyKey', 'CryptGenRandom', 'DecryptFileA', 'FlushEfsCache']

helper =['ConnectNamedPipe', 'CopyFileA', 'CreateFileA', 'CreateMutexA', 'CreateMutexExA', 'DeviceIoControl', 'FindResourceA', 'FindResourceExA', 'GetModuleBaseNameA', 'GetModuleFileNameA', 'GetModuleFileNameExA', 'GetTempPathA', 'IsWoW64Process', 'MoveFileA', 'MoveFileExA', 'PeekNamedPipe', 'WriteFile', 'TerminateThread', 'CopyFile2', 'CopyFileExA', 'CreateFile2', 'GetTempFileNameA', 'TerminateProcess', 'SetCurrentDirectory', 'FindClose', 'SetThreadPriority', 'UnmapViewOfFile', 'ControlService', 'ControlServiceExA', 'CreateServiceA', 'DeleteService', 'OpenSCManagerA', 'OpenServiceA', 'RegOpenKeyA', 'RegOpenKeyExA', 'StartServiceA', 'StartServiceCtrlDispatcherA', 'RegCreateKeyExA', 'RegCreateKeyA', 'RegSetValueExA', 'RegSetKeyValueA', 'RegDeleteValueA', 'RegOpenKeyExA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegGetValueA', 'RegFlushKey', 'RegGetKeySecurity', 'RegLoadKeyA', 'RegLoadMUIStringA', 'RegOpenCurrentUser', 'RegOpenKeyTransactedA', 'RegOpenUserClassesRoot', 'RegOverridePredefKey', 'RegReplaceKeyA', 'RegRestoreKeyA', 'RegSaveKeyA', 'RegSaveKeyExA', 'RegSetKeySecurity', 'RegUnLoadKeyA', 'RegConnectRegistryA', 'RegCopyTreeA', 'RegCreateKeyTransactedA', 'RegDeleteKeyA', 'RegDeleteKeyExA', 'RegDeleteKeyTransactedA', 'RegDeleteKeyValueA', 'RegDeleteTreeA', 'RegDeleteValueA', 'RegCloseKey', 'NtClose', 'NtCreateFile', 'NtDeleteKey', 'NtDeleteValueKey', 'NtMakeTemporaryObject', 'NtSetContextThread', 'NtSetInformationProcess', 'NtSetInformationThread', 'NtSetSystemEnvironmentValueEx', 'NtSetValueKey', 'NtShutdownSystem', 'NtTerminateProcess', 'NtTerminateThread', 'RtlSetProcessIsCritical', 'DrawTextExA', 'GetDesktopWindow', 'SetClipboardData', 'SetWindowLongA', 'SetWindowLongPtrA', 'OpenClipboard', 'SetForegroundWindow', 'BringWindowToTop', 'SetFocus', 'ShowWindow', 'NetShareSetInfo', 'NetShareAdd', 'NtQueryTimer']

#convert all item of list to lower case for comparision
enumeration_lower = [item.lower() for item in enumeration]
injection_lower =[item.lower() for item in injection]
evasion_lower = [item.lower() for item in evasion]
spying_lower = [item.lower() for item in spying]
internet_lower = [item.lower() for item in internet]
anti_debugging_lower = [item.lower() for item in anti_debugging]
ransomware_lower = [item.lower() for item in ransomware]
helper_lower = [item.lower() for item in helper]




#mapping result will be stored as a dictonary where
#key will the function_name found in the exe and
#value will be a list having 0 or 1 showing mapping in
#enumeration, injection,evasion,spying,internet, anti_debugging, ransomware, helper
attack_list = ['enumeration', 'injection','evasion','spying','internet', 'anti_debugging', 'ransomware', 'helper']

import pefile
import os,sys
import argparse
from write2pdf import mapping2pdf,normalize_list



#extract the API from exe
#robustness to defy prevention method from the attackers

def extract_functions(pe):
    result =[]
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        #dll_name = entry.dll.decode('utf-8')
        for func in entry.imports:
            #print("\t%s" % func.name.decode('utf-8'))
            result.append(func.name.decode('utf-8'))
    return result



#print(IMPORTED_FUNCTIONS, len(IMPORTED_FUNCTIONS))



# map the apis
#method 1: simple itreation
def mapping(IMPORTED_FUNCTIONS):
    MAP_RESULTS ={}
    #attack name as key and all function as value in a list
    FUNCTION_ATTACK ={attack_name:[] for attack_name in attack_list}
    for function_name in IMPORTED_FUNCTIONS:
        mapping =[]
        function_name_lower= function_name.lower()
        if function_name_lower in enumeration_lower:
            mapping.append(1)
            FUNCTION_ATTACK['enumeration'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in injection_lower:
            mapping.append(1)
            FUNCTION_ATTACK['injection'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in evasion_lower:
            mapping.append(1)
            FUNCTION_ATTACK['evasion'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in spying_lower:
            mapping.append(1)
            FUNCTION_ATTACK['spying'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in internet_lower:
            mapping.append(1)
            FUNCTION_ATTACK['internet'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in anti_debugging_lower:
            mapping.append(1)
            FUNCTION_ATTACK['anti_debugging'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in ransomware_lower:
            mapping.append(1)
            FUNCTION_ATTACK['ransomware'].append(function_name)
        else:
            mapping.append(0)
        if function_name_lower in helper_lower:
            mapping.append(1)
            FUNCTION_ATTACK['helper'].append(function_name)
        else:
            mapping.append(0)

        MAP_RESULTS[function_name]=mapping
    return MAP_RESULTS, FUNCTION_ATTACK


#show the mapping (image, list etc.)
#1. attack cateorgy and number of functions call and list of functions

#2. Tablular : each row for has
#function_name, enumeration, injection,evasion,spying,internet,anti_debugging, ransomware, helper
#for key,value in MAP_RESULTS.items():
#    print(key,value)
def show_mapping(FUNCTION_ATTACK):
    for key,value in FUNCTION_ATTACK.items():
        if value:
            print(key.capitalize())
            for item in value:
                print("\t-{}".format(item))



parser = argparse.ArgumentParser(prog='F2A Mapper', description='Extract and map DLL functions with attack class.',epilog='Enjoy the Malware Analysis! :)')
parser.add_argument('filepath', metavar='path', type=str,  help='input file for mapping')
parser.add_argument('-m','--map', dest = 'mapper', action='store_true',  help='extract function, perform mapping')

args = parser.parse_args()
print(args)

#read the file
exe_path = args.filepath

"""
if not os.path.isdir(exe_path):
    print('The file path specified does not exist')
    sys.exit()
"""
try:
    pe = pefile.PE(exe_path)
    IMPORTED_FUNCTIONS=  extract_functions(pe)
    if args.mapper:
        MAP_RESULTS, FUNCTION_ATTACK = mapping(IMPORTED_FUNCTIONS)
        FUNCTION_ATTACK = normalize_list(FUNCTION_ATTACK)
        mapping2pdf(FUNCTION_ATTACK,exe_path)
        show_mapping(FUNCTION_ATTACK)
except OSError as e:
    print(e)
except pefile.PEFormatError as e:
    print("[-] PEFormatError: %s" % e.value)
