# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "lookup the specified bytes in user modules" -f '
        'LookupBytes.lookup_bytes blookup')


def lookup_bytes(debugger, command, result, internal_dict):
    """
    lookup the specified bytes in user modules
    """
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser()
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if len(args) == 0:
        result.AppendMessage(parser.get_usage())
        return
    elif len(args) == 1:
        input_arg = args[0].replace("'", "")
        comps = input_arg.split('\\x')
        bytes_list = [int(x, 16) for x in comps if len(x) > 0]
    else:
        bytes_list = [int(x, 16) for x in args]

    bytes_len = len(bytes_list)
    input_bytes = bytes(bytes_list)

    print('lookup bytes, this may take a while')
    target = debugger.GetSelectedTarget()
    bundle_path = target.GetExecutable().GetDirectory()
    total_count = 0
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        hits_count = 0
        result.AppendMessage("-----try to lookup bytes in %s-----" % name)
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name != "__TEXT":
                continue

            for sec in seg:
                sec_name = sec.GetName()
                if "_stub" in sec_name or \
                        "__objc_methname" == sec_name or \
                        "__objc_classname" == sec_name or \
                        "__objc_methtype" == sec_name or \
                        "__cstring" == sec_name or \
                        "__ustring" == sec_name or \
                        "__gcc_except_tab" == sec_name or \
                        "__const" == sec_name or \
                        "__unwind_info" == sec_name:
                    continue

                sec_addr = sec.GetLoadAddress(target)
                error = lldb.SBError()
                sec_size = sec.GetByteSize()

                # 砸壳应用读取不到
                # sec_data = sec.GetSectionData().ReadRawData(error, 0, sec_size)
                sec_data = target.ReadMemory(lldb.SBAddress(sec_addr, target), sec_size, error)
                if not error.Success():
                    result.AppendMessage('read section {}:0x{:x} failed! {}'.format(sec_name, sec_addr, error.GetCString()))
                    continue

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    hits_count += 1
                    total_count += 1
                    bytes_addr = pos + sec_addr
                    inst_addr = target.ResolveLoadAddress(bytes_addr)
                    result.AppendMessage('address = 0x{:x} where = {}'.format(bytes_addr, inst_addr))

                    pos += bytes_len

        if hits_count == 0:
            result.AppendMessage("input bytes not found")

    result.AppendMessage("{} locations found".format(total_count))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "for example:\n" + \
            "\t%prog \\xc0\\x03\\x5f\\xd6\n" + \
            "or\n" + \
            "\t%prog c0 03 5f d6"

    parser = optparse.OptionParser(usage=usage, prog='blookup')

    return parser
