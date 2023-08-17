# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "print the address of main function" -f '
        'EntryPoint.get_main main')


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

    main_addr = get_entry_point(debugger)

    result.AppendMessage("function main at {}".format(main_addr))


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
    
    [NSString stringWithFormat:@"0x%llx(fileoff: 0x%llx)", entry_addr, entry_lc->entryoff];
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        print('execute JIT code failed:\n{}'.format(res.GetError()))
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


def generate_option_parser():
    usage = "usage: %prog [options] ModuleName\n" + \
            "Use '%prog -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog='mtrace_fs')
    parser.add_option("-m", "--method",
                      action="store_false",
                      default=True,
                      dest="method",
                      help="only trace objc method")
    parser.add_option("-1", "--oneshot",
                      action="store_false",
                      default=True,
                      dest="oneshot",
                      help="oneshot")
    parser.add_option("-H", "--humanized",
                      action="store_true",
                      default=False,
                      dest="humanized",
                      help="print humanized backtrace, but higher cost than default")

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    parser.add_option("-i", "--individual",
                      action="store_true",
                      default=False,
                      dest="individual",
                      help="create breakpoints with individual mode")

    return parser
