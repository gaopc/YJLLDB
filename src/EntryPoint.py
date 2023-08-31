# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import util
import json


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.get_main main')

    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.break_main bmain')


def get_main(debugger, command, result, internal_dict):
    """
    print the address of main function
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
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

    main_info_str = get_entry_point(debugger)
    if main_info_str:
        main_info = json.loads(main_info_str)
        result.AppendMessage("function main at 0x{:x}, fileoff: 0x{:x}".
                             format(main_info['load_addr'], main_info['file_addr']))


def break_main(debugger, command, result, internal_dict):
    """
    break the main function
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
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

    main_info_str = get_entry_point(debugger)

    if len(main_info_str) == 0:
        return

    main_info = json.loads(main_info_str)
    target = debugger.GetSelectedTarget()
    main_load_addr = main_info['load_addr']
    main_addr = target.ResolveLoadAddress(main_load_addr)
    brkpoint = target.BreakpointCreateBySBAddress(main_addr)
    # 判断下断点是否成功
    if not brkpoint.IsValid() or brkpoint.num_locations == 0:
        result.AppendMessage(("Breakpoint isn't valid or hasn't found any hits"))
    else:
        result.AppendMessage(("Breakpoint {}: {}, address = 0x{:x}"
                              .format(brkpoint.GetID(), util.get_desc_for_address(main_addr), main_load_addr)
                              ))


def get_entry_point(debugger):
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
    struct entry_point_command {
        uint32_t  cmd;    /* LC_MAIN only used in MH_EXECUTE filetypes */
        uint32_t  cmdsize;    /* 24 */
        uint64_t  entryoff;    /* file (__TEXT) offset of main() */
        uint64_t  stacksize;/* if not zero, initial stack size */
    };
    '''
    command_script += r'''
    NSString *x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    
    const mach_header_t *x_mach_header = NULL;
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
            break;
        }
    }
    
    struct entry_point_command *entry_lc = NULL;
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0x80000028) { //LC_MAIN
                        entry_lc = (struct entry_point_command *)sc;
                        break;
                    }
                }
            }
        }
    }
    
    uint64_t entry_addr = (uint64_t)x_mach_header + entry_lc->entryoff;
    
    NSDictionary *main_info = @{
        @"file_addr": @(entry_lc->entryoff),
        @"load_addr": @(entry_addr)
    };
    NSData *json_data = [NSJSONSerialization dataWithJSONObject:main_info options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:json_data encoding:4];
    json_str;
    '''

    ret_str = util.exe_script(debugger, command_script)

    return ret_str


def generate_option_parser():
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='main')

    return parser
