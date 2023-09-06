# -*- coding: UTF-8 -*-

import json
import shlex
import lldb
import os

g_arm64_nop_bytes = b'\x1f\x20\x03\xd5'
g_x64_nops = {
    1: b'\x90',
    2: b'\x66\x90',
    3: b'\x0F\x1F\x00',
    4: b'\x0F\x1F\x40\x00',
    5: b'\x0F\x1F\x44\x00\x00',
    6: b'\x66\x0F\x1F\x44\x00\x00',
    7: b'\x0F\x1F\x80\x00\x00\x00\x00',
    8: b'\x0F\x1F\x84\x00\x00\x00\x00\x00',
    9: b'\x66\x0F\x1F\x84\x00\x00\x00\x00\x00',
}


def get_desc_for_address(addr, default_name=None, need_line=True):
    symbol = addr.GetSymbol()

    module = addr.GetModule()
    module_name = "unknown"
    if module:
        module_file_spec = module.GetFileSpec()
        module_path = module_file_spec.GetFilename()
        module_name = os.path.basename(module_path)

    if need_line:
        line_entry = addr.GetLineEntry()
        if line_entry:
            file_spec = line_entry.GetFileSpec()
            file_path = file_spec.GetFilename()
            file_name = os.path.basename(file_path)
            return "{}`{} at {}:{}:{}".format(module_name, symbol.GetName(), file_name, line_entry.GetLine(),
                                              line_entry.GetColumn())

    sym_name = symbol.GetName()
    if default_name and '___lldb_unnamed_symbol' in sym_name:
        sym_name = default_name

    return "{}`{}".format(module_name, sym_name)


def exe_script(command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = lldb.debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        print('execute JIT code failed: \n{}'.format(res.GetError()))
        return ''

    response = res.GetOutput()

    response = response.strip()
    # 末尾有两个\n
    if response.endswith('\n\n'):
        response = response[:-2]
    # 末尾有一个\n
    if response.endswith('\n'):
        response = response[:-1]

    return response


def try_mkdir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def is_x64():
    platform = lldb.debugger.GetSelectedPlatform()
    triple = platform.GetTriple()

    return 'x86_64' in triple


def gen_nop(size):
    new_bytes = b''
    if is_x64():  # x86_64 ios-simulator
        loop_count = int(size / 4)
        for _ in range(loop_count):
            new_bytes += g_x64_nops[4]
        mod = size % 4
        if mod > 0:
            new_bytes += g_x64_nops[mod]
    else:
        loop_count = int(size / 4)
        for _ in range(loop_count):
            new_bytes += g_arm64_nop_bytes

    return new_bytes
