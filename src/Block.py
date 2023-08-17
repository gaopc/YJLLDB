# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "find global blocks in user modules" -f '
        'Block.find_global_blocks blocks')

    debugger.HandleCommand(
        'command script add -h "find the specified block(s) in user modules" -f '
        'Block.find_blocks fblock')

    debugger.HandleCommand(
        'command script add -h "break global blocks in user modules" -f '
        'Block.break_global_blocks bblocks')


def find_global_blocks(debugger, command, result, internal_dict):
    """
    find global blocks in user modules
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('blocks')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

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

        print("-----try look up block in %s-----" % name)
        blocks_info = get_blocks_info(debugger, name)
        if not blocks_info or 'empty description' in blocks_info:
            continue

        blocks_info_list = blocks_info.split(';')
        if len(blocks_info_list) == 0:
            print('no block found in {}'.format(name))
            continue

        global_blocks = []
        block_addrs = []
        block_funcs = []
        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addrs.append(int(comps[1], 16))
            block_funcs.append(int(comps[2], 16))

        hits_count = 0
        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()

            # 过滤析构函数
            if "::~" in sym_name:
                continue
            # 过滤objc_msgSend stubs
            if sym_name.startswith("objc_msgSend$"):
                continue

            """
            调用系统库c++函数和operator也会在__TEXT.__text产生一个函数
            (lldb) br list 13293.1
            13293: address = demo[0x00000001000774d8], locations = 1, resolved = 1, hit count = 1
              13293.1: where = demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
              [abi:v15006](unsigned long) at vector:1455, address = 0x00000001004a74d8, resolved, hit count = 1 

            (lldb) image lookup -a 0x00000001004a74d8
                  Address: demo[0x00000001000774d8] (demo.__TEXT.__text + 463104)
                  Summary: demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
                  [abi:v15006](unsigned long) at vector:1455
            """

            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            insts = symbol.GetInstructions(target)

            # debug block作为函数参数
            # adrp   x6, 4
            # add    x6, x6, #0x188

            # release block作为函数参数
            # adr    x2,  # 0x2c14

            # deubg 全局block变量被使用
            # adrp   x8, 5
            # ldr    x0, [x8, #0x7e8]
            # ldr    x8, [x0, #0x10]
            # blr    x8

            # deubg 全局block变量，在一个函数中被多次使用
            # adrp   x8, 5
            # str    x8, [sp, #0x30]
            # ldr    x0, [x8, #0x7e8]
            # ldr    x8, [x0, #0x10]
            # blr    x8

            # release 全局block变量被使用 (还未适配)
            # ldr    x0, #0x4468
            # ldr    x8, [x0, #0x10]
            # blr    x8

            adrp_ins = None
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == 'adr':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: adr {}'.format(next_ins.GetAddress().GetLoadAddress(target), adr_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 2:
                        continue

                    if '#' not in adr_op_list[1]:
                        continue

                    adr_addr = next_ins.GetAddress().GetLoadAddress(target)
                    try:
                        adr_offset = int(adr_op_list[1].replace('#', ''), 16)
                    except Exception as error:
                        print(error)
                        continue

                    target_addr = adr_addr + adr_offset
                    next_ins_addr = next_ins.GetAddress()
                    # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                    try:
                        idx = block_addrs.index(target_addr)
                        print('find a block: 0x{:x} in {}'.format(target_addr,
                                                                  get_desc_for_address(next_ins_addr)))
                        block_addrs.remove(target_addr)
                        block_funcs.remove(block_funcs[idx])
                        hits_count += 1
                        total_count += 1
                    except Exception as error:
                        pass
                elif next_ins.GetMnemonic(target) == 'adrp':
                    adrp_ins = next_ins
                    adrp_addr = adrp_ins.GetAddress().GetLoadAddress(target)
                    adrp_ins_ops = adrp_ins.GetOperands(target).replace(' ', '')
                    adrp_op_list = adrp_ins_ops.split(',')
                elif adrp_ins and next_ins.GetMnemonic(target) == 'add':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: add {}'.format(next_ins.GetAddress().GetLoadAddress(target), next_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 3:
                        continue
                    if '#' not in adr_op_list[2]:
                        continue

                    adr_offset = int(adr_op_list[2].replace('#', ''), 16)
                    target_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset
                    next_ins_addr = next_ins.GetAddress()
                    # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                    try:
                        idx = block_addrs.index(target_addr)
                        print('find a block: 0x{:x} in {}'.format(target_addr,
                                                                  get_desc_for_address(next_ins_addr)))
                        block_addrs.remove(target_addr)
                        block_funcs.remove(block_funcs[idx])
                        hits_count += 1
                        total_count += 1
                    except Exception as error:
                        pass

                    adrp_ins = None
                elif adrp_ins and next_ins.GetMnemonic(target) == 'ldr':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: ldr {}'.format(next_ins.GetAddress().GetLoadAddress(target), next_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 3:
                        continue

                    operand = adr_op_list[2]
                    if ']' not in operand:
                        continue

                    if ']!' in operand:
                        continue

                    if '#' not in operand:
                        continue

                    operand = operand.replace('#', '')
                    operand = operand.replace(']', '')

                    try:
                        adr_offset = int(operand, 16)
                    except Exception as error:
                        print(error)
                        adrp_ins = None
                        continue

                    ldr_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset
                    error = lldb.SBError()
                    target_addr = process.ReadPointerFromMemory(ldr_addr, error)
                    if error.Success():
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = block_addrs.index(target_addr)
                            print('using global block: 0x{:x} in {}'.format(target_addr,
                                                                            get_desc_for_address(next_ins_addr)))
                            if global_blocks.count(target_addr) == 0:
                                hits_count += 1
                                total_count += 1
                                global_blocks.append(target_addr)
                        except Exception as error:
                            pass

                    adrp_ins = None
                elif adrp_ins and next_ins.GetMnemonic(target) == 'str':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    adr_op_list = adr_ins_ops.split(',')
                    if adr_op_list[0] != adrp_op_list[0]:
                        adrp_ins = None
                else:
                    adrp_ins = None

                if len(block_addrs) == 0:
                    break

            if len(block_addrs) == 0:
                break

        for index, block_addr in enumerate(block_addrs):
            if global_blocks.count(block_addr) > 0:
                continue
            block_func = block_funcs[index]
            func_addr = target.ResolveLoadAddress(block_func)
            print('unresolved block: 0x{:x} in {}'.format(block_addr, get_desc_for_address(func_addr)))

        if hits_count == 0:
            print("no block resolved")

    result.AppendMessage("{} block(s) resolved".format(total_count))


def find_blocks(debugger, command, result, internal_dict):
    """
    find the specified block(s) in user modules
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('fblock', ' [address] [address]')
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
    else:
        all_addr_list = []
        for arg in args:
            value = int(arg, 16)
            if value % 8:
                print('0x{:x} could not be a block object'.format(value))
                continue

            all_addr_list.append(value)

    if len(all_addr_list) == 0:
        return

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

        print("-----try look up block in %s-----" % name)
        blocks_info = get_blocks_info(debugger, name)
        if not blocks_info or 'empty description' in blocks_info:
            continue

        blocks_info_list = blocks_info.split(';')
        if len(blocks_info_list) == 0:
            print('no block found in {}'.format(name))
            continue

        global_blocks = []
        addr_list = []
        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addr = int(comps[1], 16)
            if block_addr in all_addr_list:
                addr_list.append(block_addr)
                all_addr_list.remove(block_addr)

        if len(addr_list) == 0:
            continue

        for symbol in module:
            # 2为Code，5为Trampoline，即调用的系统函数
            if symbol.GetType() != 2:
                continue

            sym_name = symbol.GetName()
            sym_start_addr = symbol.GetStartAddress()

            # 过滤析构函数
            if "::~" in sym_name:
                continue
            # 过滤objc_msgSend stubs
            if sym_name.startswith("objc_msgSend$"):
                continue

            """
            调用系统库c++函数和operator也会在__TEXT.__text产生一个函数
            (lldb) br list 13293.1
            13293: address = demo[0x00000001000774d8], locations = 1, resolved = 1, hit count = 1
              13293.1: where = demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
              [abi:v15006](unsigned long) at vector:1455, address = 0x00000001004a74d8, resolved, hit count = 1 

            (lldb) image lookup -a 0x00000001004a74d8
                  Address: demo[0x00000001000774d8] (demo.__TEXT.__text + 463104)
                  Summary: demo`std::__1::vector<unsigned char, std::__1::allocator<unsigned char> >::operator[]
                  [abi:v15006](unsigned long) at vector:1455
            """

            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            insts = symbol.GetInstructions(target)

            adrp_ins = None
            for next_ins in insts:
                if next_ins.GetMnemonic(target) == 'adr':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: adr {}'.format(next_ins.GetAddress().GetLoadAddress(target), adr_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 2:
                        continue

                    if '#' not in adr_op_list[1]:
                        continue

                    adr_addr = next_ins.GetAddress().GetLoadAddress(target)
                    adr_offset = int(adr_op_list[1].replace('#', ''), 16)
                    target_addr = adr_addr + adr_offset
                    next_ins_addr = next_ins.GetAddress()
                    # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                    try:
                        idx = addr_list.index(target_addr)
                        print('find a block: 0x{:x} in {}'.format(target_addr,
                                                                  get_desc_for_address(next_ins_addr)))
                        addr_list.remove(target_addr)
                        total_count += 1
                    except Exception as error:
                        pass
                elif next_ins.GetMnemonic(target) == 'adrp':
                    adrp_ins = next_ins
                    adrp_addr = adrp_ins.GetAddress().GetLoadAddress(target)
                    adrp_ins_ops = adrp_ins.GetOperands(target).replace(' ', '')
                    adrp_op_list = adrp_ins_ops.split(',')
                elif adrp_ins and next_ins.GetMnemonic(target) == 'add':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: add {}'.format(next_ins.GetAddress().GetLoadAddress(target), next_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 3:
                        continue
                    if '#' not in adr_op_list[2]:
                        continue

                    adr_offset = int(adr_op_list[2].replace('#', ''), 16)
                    target_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset
                    next_ins_addr = next_ins.GetAddress()
                    # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                    try:
                        idx = addr_list.index(target_addr)
                        print('find a block: 0x{:x} in {}'.format(target_addr,
                                                                  get_desc_for_address(next_ins_addr)))
                        addr_list.remove(target_addr)
                        total_count += 1
                    except Exception as error:
                        pass

                    adrp_ins = None
                elif adrp_ins and next_ins.GetMnemonic(target) == 'ldr':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    # print('0x{:x}: ldr {}'.format(next_ins.GetAddress().GetLoadAddress(target), next_ins_ops))
                    adr_op_list = adr_ins_ops.split(',')
                    if len(adr_op_list) != 3:
                        continue

                    operand = adr_op_list[2]
                    if ']' not in operand:
                        continue

                    if ']!' in operand:
                        continue

                    if '#' not in operand:
                        continue

                    operand = operand.replace('#', '')
                    operand = operand.replace(']', '')

                    adr_offset = int(operand, 16)
                    ldr_addr = (adrp_addr & 0xFFFFFFFFFFFFF000) + (int(adrp_op_list[-1]) * 4096) + adr_offset
                    error = lldb.SBError()
                    target_addr = process.ReadPointerFromMemory(ldr_addr, error)
                    if error.Success():
                        next_ins_addr = next_ins.GetAddress()
                        # print('target_addr: 0x{:x} {}'.format(target_addr, next_ins_addr))
                        try:
                            idx = addr_list.index(target_addr)
                            print('using global block: 0x{:x} in {}'.format(target_addr,
                                                                            get_desc_for_address(next_ins_addr)))
                            if global_blocks.count(target_addr) == 0:
                                global_blocks.append(target_addr)
                                total_count += 1
                        except Exception as error:
                            pass

                    adrp_ins = None
                elif adrp_ins and next_ins.GetMnemonic(target) == 'str':
                    adr_ins_ops = next_ins.GetOperands(target).replace(' ', '')
                    adr_op_list = adr_ins_ops.split(',')
                    if adr_op_list[0] != adrp_op_list[0]:
                        adrp_ins = None
                else:
                    adrp_ins = None

                if len(addr_list) == 0:
                    break

            if len(addr_list) == 0:
                break

        for block_addr in addr_list:
            print('block: 0x{:x} not found'.format(block_addr))
            addr_list.remove(block_addr)

        if len(all_addr_list) == 0:
            break

    for block_addr in all_addr_list:
        print('block: 0x{:x} not found'.format(block_addr))

    result.AppendMessage("{} location(s) found".format(total_count))


def break_global_blocks(debugger, command, result, internal_dict):
    """
    find global blocks in user modules
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('bblocks')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    module_list = args

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

        if len(module_list) and name not in module_list:
            continue

        print("-----try look up block in %s-----" % name)
        blocks_info = get_blocks_info(debugger, name)
        if not blocks_info or 'empty description' in blocks_info:
            continue

        blocks_info_list = blocks_info.split(';')
        if len(blocks_info_list) == 0:
            print('no block found in {}'.format(name))
            continue

        for block_info in blocks_info_list:
            # print("block_info: {}".format(block_info))
            comps = block_info.split(':')
            block_addr = int(comps[1], 16)
            block_func = int(comps[2], 16)

            block_func_addr = target.ResolveLoadAddress(block_func)
            brkpoint = target.BreakpointCreateBySBAddress(block_func_addr)
            # 判断下断点是否成功
            if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                print("Breakpoint isn't valid or hasn't found any hits")
            else:
                total_count += 1
                print("break block: 0x{:x} with Breakpoint {}: {}, address = 0x{:x}"
                      .format(block_addr, brkpoint.GetID(), get_desc_for_address(block_func_addr), block_func)
                      )

    result.AppendMessage("set {} breakpoints".format(total_count))


def get_desc_for_address(addr):
    symbol = addr.GetSymbol()

    module = addr.GetModule()
    module_name = "unknown"
    if module:
        module_file_spec = module.GetFileSpec()
        module_path = module_file_spec.GetFilename()
        module_name = os.path.basename(module_path)

    line_entry = addr.GetLineEntry()
    if line_entry:
        file_spec = line_entry.GetFileSpec()
        file_path = file_spec.GetFilename()
        file_name = os.path.basename(file_path)
        return "{}`{} at {}:{}:{}".format(module_name, symbol.GetName(), file_name, line_entry.GetLine(),
                                          line_entry.GetColumn())

    return "{}`{}".format(module_name, symbol.GetName())


def get_blocks_info(debugger, module):
    command_script = '@import Foundation;'
    command_script += r'''
    struct mach_header_64 {
        uint32_t    magic;        /* mach magic number identifier */
        int32_t        cputype;    /* cpu specifier */
        int32_t        cpusubtype;    /* machine specifier */
        uint32_t    filetype;    /* type of file */
        uint32_t    ncmds;        /* number of load commands */
        uint32_t    sizeofcmds;    /* the size of all the load commands */
        uint32_t    flags;        /* flags */
        uint32_t    reserved;    /* reserved */
    };

    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;        /* memory address of this segment */
        uint64_t    vmsize;        /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;    /* amount to map from the file */
        int32_t        maxprot;    /* maximum VM protection */
        int32_t        initprot;    /* initial VM protection */
        uint32_t    nsects;        /* number of sections in segment */
        uint32_t    flags;        /* flags */
    };
    struct section_64 { /* for 64-bit architectures */
        char		sectname[16];	/* name of this section */
        char		segname[16];	/* segment this section goes in */
        uint64_t	addr;		/* memory address of this section */
        uint64_t	size;		/* size in bytes of this section */
        uint32_t	offset;		/* file offset of this section */
        uint32_t	align;		/* section alignment (power of 2) */
        uint32_t	reloff;		/* file offset of relocation entries */
        uint32_t	nreloc;		/* number of relocation entries */
        uint32_t	flags;		/* flags (section type and attributes)*/
        uint32_t	reserved1;	/* reserved (for offset or index) */
        uint32_t	reserved2;	/* reserved (for count or sizeof) */
        uint32_t	reserved3;	/* reserved */
    };
    #define __LP64__ 1
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
    struct load_command {
        uint32_t cmd;		/* type of load command */
        uint32_t cmdsize;	/* total size of command in bytes */
    };
    '''
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (!x_module_name) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }

    const mach_header_t *x_mach_header = NULL;
    intptr_t slide = 0;
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);

        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:x_module_name]) {
            x_mach_header = mach_header;
            slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    struct segment_command_64 *data_seg = NULL;
    struct section_64 *data_const_sec = NULL;
    uint32_t magic = x_mach_header->magic;
    if (magic == 0xfeedfacf) { // MH_MAGIC_64
        uint32_t ncmds = x_mach_header->ncmds;
        if (ncmds > 0) {
            uintptr_t cur = (uintptr_t)x_mach_header + sizeof(mach_header_t);
            struct load_command *sc = NULL;
            for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                sc = (struct load_command *)cur;
                if (sc->cmd == 0x19) { // LC_SEGMENT_64
                    struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                    if (strcmp(seg->segname, "__DATA") == 0) { //SEG_DATA
                        data_seg = seg;

                        uint32_t nsects = seg->nsects;
                        char *sec_start = (char *)seg + sizeof(struct segment_command_64);
                        size_t sec_size = sizeof(struct section_64);
                        for (uint32_t idx = 0; idx < nsects; idx++) {
                            struct section_64 *sec = (struct section_64 *)sec_start;
                            char *sec_name = strndup(sec->sectname, 16);
                            if (strcmp(sec_name, "__const") == 0) {
                                data_const_sec = sec;
                                break;
                            }

                            sec_start += sec_size;
                            if (sec_name) {
                                free(sec_name);
                            }
                        }
                    }
                }
            }
        }
    }

    void *globalBlock = &_NSConcreteGlobalBlock;
    void *stackBlock = &_NSConcreteStackBlock;
    NSMutableString *blocksInfo = [NSMutableString string];
    uint64_t sec_offset = data_const_sec->offset - data_seg->fileoff;
    if (data_const_sec) {
        uint64_t sec_size = data_const_sec->size;
        int pointer_size = sizeof(void *);
        uint64_t count = sec_size / pointer_size;
        void **ptr = (void **)(slide + data_const_sec->addr);
        for (uint64_t i = 0; i < count; i++) {
            void *tmp = ptr[i];
            if (tmp == globalBlock || tmp == stackBlock) {
                uint64_t offset =  sec_offset + i * pointer_size;
                [blocksInfo appendFormat:@"0x%llx:%p:%p;", offset, &ptr[i], ptr[i + 2]];
            }
        }
    }
    NSUInteger len = [blocksInfo length];
    if (len > 0) {
        [blocksInfo replaceCharactersInRange:NSMakeRange(len - 1, 1) withString:@""];
    }
    blocksInfo;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


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


def generate_option_parser(proc, args=''):
    usage = "usage: %prog{}\n".format(args)

    parser = optparse.OptionParser(usage=usage, prog=proc)

    return parser
