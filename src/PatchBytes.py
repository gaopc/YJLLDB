# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex

g_nop_bytes = b'\x1f\x20\x03\xd5'


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "patch bytes in user modules" -f PatchBytes.patch patch')


def patch(debugger, command, result, internal_dict):
    """
    patch bytes in user modules
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

    if len(args) == 0 and not options.size:
        result.AppendMessage(parser.get_usage())
        return
    elif len(args) == 1:
        input_arg = args[0].replace("'", "")
        comps = input_arg.split('\\x')
        bytes_list = [int(x, 16) for x in comps if len(x) > 0]
    else:
        bytes_list = [int(x, 16) for x in args]

    if options.address:
        if options.size:
            size = int(options.size)
        else:
            size = len(bytes_list)

        address_str = options.address
        if address_str.startswith('0x'):
            address = int(address_str, 16)
        else:
            address = int(address_str)

        patch_addr_with_bytes(debugger, result, address, size, bytes_list)
    else:
        patch_all_matched_bytes_with_nop(debugger, result, bytes_list)


def patch_all_matched_bytes_with_nop(debugger, result, bytes_list):
    bytes_len = len(bytes_list)
    if bytes_len % 4 != 0:
        result.SetError("The number of bytes must be a multiple of 4")
        return
    input_bytes = bytes(bytes_list)

    print('lookup bytes, this may take a while')
    loop_count = int(bytes_len / 4)
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
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
        result.AppendMessage("-----try to patch bytes in %s-----" % name)
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
                error1 = lldb.SBError()
                sec_size = sec.GetByteSize()

                # 砸壳应用读取不到
                # sec_data = sec.GetSectionData().ReadRawData(error, 0, sec_size)
                sec_data = target.ReadMemory(lldb.SBAddress(sec_addr, target), sec_size, error1)
                if not error1.Success():
                    result.AppendMessage('read section {}:0x{:x} failed! {}'.format(sec_name, sec_addr, error1.GetCString()))
                    continue

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    hits_count += 1
                    total_count += 1
                    bytes_addr = pos + sec_addr
                    for idx in range(loop_count):
                        to_patch = bytes_addr + idx * 4
                        error2 = lldb.SBError()
                        process.WriteMemory(to_patch, g_nop_bytes, error2)
                        if not error2.Success():
                            result.AppendMessage('patch bytes at {} failed! {}'.format(to_patch, error2.GetCString()))
                            continue

                    pos += bytes_len

        if hits_count == 0:
            result.AppendMessage("input bytes not found")

    result.AppendMessage("patch {} locations".format(total_count))


def patch_addr_with_bytes(debugger, result, addr, size, bytes_list):
    if size == 0 or size % 4 != 0:
        result.SetError("The number of bytes must be a multiple of 4")
        return

    bytes_len = len(bytes_list)
    if bytes_len > 0 and bytes_len != size:
        result.SetError("arguments error")
        return

    if bytes_len:
        new_bytes = bytes(bytes_list)
    else:
        new_bytes = b''
        loop_count = int(size / 4)
        for i in range(loop_count):
            new_bytes += g_nop_bytes

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    to_patch = addr
    error2 = lldb.SBError()
    process.WriteMemory(to_patch, new_bytes, error2)
    if error2.Success():
        result.AppendMessage('patch {} bytes at 0x{:x} success'.format(len(new_bytes), to_patch))
    else:
        result.AppendMessage('patch bytes at {} failed! {}'.format(to_patch, error2.GetCString()))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "examples:\n" + \
            "\t1. %prog \\xc0\\x03\\x5f\\xd6\n" + \
            "\t2. %prog c0 03 5f d6\n" + \
            "\t3. %prog -a 0x12345678 \\x1f\\x20\\x03\\xd5\n" + \
            "\t4. %prog -a 0x12345678 1f 20 03 d5\n" + \
            "\t5. %prog -a 0x12345678 -s 4"

    parser = optparse.OptionParser(usage=usage, prog='patch')
    parser.add_option("-a", "--address",
                      action="store",
                      dest="address",
                      help="address to path")
    parser.add_option("-s", "--size",
                      action="store",
                      dest="size",
                      help="size to path")

    return parser
