# -*- coding: UTF-8 -*-

import json
import shlex
import lldb
import os


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


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
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

