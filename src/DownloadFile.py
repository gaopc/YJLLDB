# -*- coding: UTF-8 -*-

import json
import lldb
import optparse
import shlex
import os.path


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "download file from device" -f '
        'DownloadFile.download_file dfile')
    debugger.HandleCommand(
        'command script add -h "download directory from device" -f '
        'DownloadFile.download_dir ddir')


def download_file(debugger, command, result, internal_dict):
    """
    download file from device
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('dfile')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if len(args) == 0:
        print(parser.get_usage())
        return

    for filepath in args:
        file_info_str = load_file(debugger, filepath)
        if file_info_str:
            file_info = json.loads(file_info_str)
            print('dumping {}, this may take a while'.format(file_info["file_name"]))
            dump_file_with_info(debugger, file_info)


def download_dir(debugger, command, result, internal_dict):
    """
    download directory from device
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('ddir')
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if len(args) == 0:
        print(parser.get_usage())
        return

    for filepath in args:
        dir_info_str = load_dir(debugger, filepath)
        if dir_info_str:
            dir_info = json.loads(dir_info_str)
            print('dumping {}, this may take a while'.format(dir_info["dir_name"]))
            dump_dir_with_info(debugger, dir_info)


def dump_data(debugger, output_filepath, data_size, data_addr):
    directory = os.path.dirname(output_filepath)
    try_mkdir(directory)

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    cmd = 'memory read --force --outfile {} --binary --count {} {}' \
        .format(output_filepath, data_size, data_addr)
    interpreter.HandleCommand(cmd, res)

    if res.GetError():
        print(res.GetError())
    else:
        print("{} bytes written to '{}'".format(data_size, output_filepath))


def dump_file_with_info(debugger, file_info):
    error = file_info.get("error")
    if error:
        print(error)
        return

    file_name = file_info["file_name"]
    data_info = file_info["data_info"]
    comps = data_info.split('-')
    data_addr = int(comps[0])
    data_size = int(comps[1])

    home_path = os.environ['HOME']
    output_filepath = os.path.join(home_path, file_name)
    if os.path.exists(output_filepath):
        output_filepath = os.path.join(home_path, 'dumped_' + file_name)
    dump_data(debugger, output_filepath, data_size, data_addr)


def dump_dir_with_info(debugger, dir_info):
    error = dir_info.get("error")
    if error:
        print(error)
        return

    dir_name = dir_info["dir_name"]
    home_path = os.environ['HOME']
    output_dir = os.path.join(home_path, dir_name)
    if os.path.exists(output_dir):
        output_dir = os.path.join(home_path, 'dumped_' + dir_name)

    files = dir_info["files"]
    for file_info in files:
        file_name = file_info["rel_path"]
        data_info = file_info["data_info"]

        output_filepath = os.path.join(output_dir, file_name)
        comps = data_info.split('-')
        data_addr = int(comps[0])
        data_size = int(comps[1])
        dump_data(debugger, output_filepath, data_size, data_addr)


def load_file(debugger, filepath):
    command_script = '@import Foundation;'
    command_script += 'NSString *filepath = @"' + filepath + '";'
    command_script += r'''
    BOOL isDirectory = NO;
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:filepath isDirectory:&isDirectory];
    
    NSDictionary *file_dict = nil;
    if (isDirectory) {
        file_dict = @{
            @"error": @"it's a directory, not file",
            @"file_name": filepath.lastPathComponent
        };
    } else if (exists) {
        NSData *file_data = [NSData dataWithContentsOfFile:filepath];
        NSUInteger len = [file_data length];
        const void *bytes = (const void *)[file_data bytes];
        NSString *data_info = [NSString stringWithFormat:@"%lu-%lu", (NSUInteger)bytes, len];
        
        file_dict = @{
            @"data_info": data_info,
            @"file_name": filepath.lastPathComponent
        };
    } else {
        file_dict = @{
            @"error": @"file not found",
            @"file_name": filepath.lastPathComponent
        };
    }
    
    NSData *json_data = [NSJSONSerialization dataWithJSONObject:file_dict options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:json_data encoding:4];
    json_str;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def load_dir(debugger, filepath):
    command_script = '@import Foundation;'
    command_script += 'NSString *filepath = @"' + filepath + '";'
    command_script += r'''
    BOOL isDirectory = NO;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    BOOL exists = [fileManager fileExistsAtPath:filepath isDirectory:&isDirectory];
    
    NSDictionary *file_dict = nil;
    if (!isDirectory) {
        file_dict = @{
            @"error": @"it's not a directory",
            @"dir_name": filepath.lastPathComponent
        };
    } else if (exists) {
        NSArray *subpaths = [fileManager subpathsAtPath:filepath];
        NSMutableArray *files = [NSMutableArray array];
        for (NSString *subpath in subpaths) {
            NSString *fullpath = [filepath stringByAppendingPathComponent:subpath];
            NSData *file_data = [NSData dataWithContentsOfFile:fullpath];
            NSUInteger len = [file_data length];
            const void *bytes = (const void *)[file_data bytes];
            NSString *data_info = [NSString stringWithFormat:@"%lu-%lu", (NSUInteger)bytes, len];
            
            BOOL isDirectory = NO;
            [fileManager fileExistsAtPath:fullpath isDirectory:&isDirectory];
            if (isDirectory) {
                continue;
            }
            
            [files addObject:@{
                @"rel_path": subpath,
                @"data_info": data_info,
            }];
        }
        
        file_dict = @{
            @"files": files,
            @"dir_name": filepath.lastPathComponent
        };
    } else {
        file_dict = @{
            @"error": @"directory not found",
            @"dir_name": filepath.lastPathComponent
        };
    }
    
    NSData *json_data = [NSJSONSerialization dataWithJSONObject:file_dict options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:json_data encoding:4];
    json_str;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def try_mkdir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


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


def generate_option_parser(prog):
    usage = "usage: %prog filepath [filepath]\n" + \
            "Use '%prog -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
