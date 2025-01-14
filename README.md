## YJLLDB

一些用于调试iOS应用的lldb命令。Some very useful lldb commands for iOS debugging.



## Commands list

​     \* [bab - break at bytes](#bab---break-at-bytes)

​     \* [baf - break all functions in module](#baf---break-all-functions-in-module)

​     \* [bdc - breakpoint disable current](#bdc---breakpoint-disable-current)

​     \* [symbolic](#symbolic)

​     \* [commads to get common directory](#commads-to-get-common-directory)

​     \* [ls](#ls)

​     \* [find_el - find endless loop](#find_el---find-endless-loop)

​     \* [thread_eb - extended backtrace of thread](#thread_eb---extended-backtrace-of-thread)

​     \* [entitlements - dump entitlements](#entitlements---dump-entitlements)

​     \* [segments - print segments](#segments---print-segments)

​     \* [main](#main)

​     \* [executable - print main executable name](#executable---print-main-executable-name)

​     \* [appdelegate](#appdelegate)

​     \* [classes - print class names](#classes---print-class-names)

​     \* [image_list](#image_list)

​     \* [slookup - lookup string](#slookup---lookup-string)

​     \* [blookup - lookup bytes](#blookup---lookup-bytes)

​     \* [patch](#patch)

​     \* [mtrace - trace module](#mtrace---trace-module)

​     \* [bda - breakpoint disable at class](#bda---breakpoint-disable-at-class)

​     \* [dmodule - dump module](#dmodule---dump-module)

​     \* [dapp - dump App](#dapp---dump-app)

​     \* [dfile - download file](#dfile---download-file)

​     \* [ddir - download directory](#ddir---download-directory)

​     \* [ufile - upload local file to device](#ufile---upload-local-file-to-device)

​     \* [rm - remove file](#rm---remove-file)

​     \* [fblock - find block](#fblock---find-block)

​     \* [blocks - find global blocks](#blocks---find-global-blocks)

​     \* [bblocks - break global blocks](#bblocks---break-global-blocks)

​     \* [initfunc - print mod init func](#initfunc---print-mod-init-func)

​     \* [binitfunc - break mod init func](#binitfunc---break-mod-init-func)

​     \* [bmethod - break method](#bmethod---break-method)

​     \* [bmain - break main function](#bmain---break-main-function)

## Installation

1. Clone this repo
2. Open up (or create) **~/.lldbinit**
3. Add the following command to your ~/.lldbinit file: `command script import /path/to/YJLLDB/src/yjlldb.py`

## usage

#### bab - break at bytes

Set breakpoints at the specified bytes in user modules.

```stylus
// for example, break at ret
(lldb) bab c0 03 5f d6
Breakpoint 1: where = LLDBCode`-[ViewController viewDidLoad] + 240 at ViewController.m:29:1, address = 0x1029b3008
...
set 728 breakpoints

(lldb) x 0x1029b3008
0x1029b3008: c0 03 5f d6 ff 03 03 d1 fd 7b 0b a9 fd c3 02 91  .._......{......
0x1029b3018: e8 03 01 aa e1 03 02 aa e3 0f 00 f9 a0 83 1f f8  ................
(lldb) dis -s 0x1029b3008 -c 1
LLDBCode`-[ViewController viewDidLoad]:
    0x1029b3008 <+240>: ret
```

[back to commands list](#Commands-list)



#### baf - break all functions in module

Break all functions and methods in the specified module.

For example，break UIKit:

```stylus
(lldb) baf UIKit
-----break functions in UIKit-----
will set breakpoint for 76987 names
Breakpoint 3: 75016 locations
```

[back to commands list](#Commands-list)



#### bdc - breakpoint disable current

Disable current breakpoint and continue.

```stylus
(lldb) thread info
thread #1: tid = 0x2cb739, 0x000000018354f950 libsystem_kernel.dylib`open, queue = 'com.apple.main-thread', stop reason = breakpoint 5.13

(lldb) bdc
disable breakpoint 5.13 [0x18354f950]libsystem_kernel.dylib`open
and continue
```

[back to commands list](#Commands-list)



#### symbolic

Symbolic address list.

```stylus
(lldb) symbolic (0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0)
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 Interlock`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```

or

```stylus
(lldb) symbolic 0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 Interlock`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```

[back to commands list](#Commands-list)



#### commads to get common directory

```stylus
(lldb) bundle_dir
/var/containers/Bundle/Application/63954B0E-79FA-42F2-A7EA-3568026008A1/Interlock.app
(lldb) home_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28
(lldb) doc_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Documents
(lldb) caches_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library/Caches
(lldb) lib_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library
(lldb) tmp_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/tmp
(lldb) group_dir
/private/var/mobile/Containers/Shared/AppGroup/9460EA21-AE6A-4220-9BB3-6EC8B971CDAE
```

[back to commands list](#Commands-list)



#### ls 

List directory contents, just like `ls -lh` on Mac.

```stylus
(lldb) ls bu
/var/containers/Bundle/Application/D0419A6E-053C-4E35-B422-7C0FD6CAB060/Interlock.app
drwxr-xr-x        128B 1970-01-01 00:00:00 +0000 Base.lproj
drwxr-xr-x         96B 1970-01-01 00:00:00 +0000 _CodeSignature
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 META-INF
-rw-r--r--        1.5K 2023-05-16 03:17:32 +0000 Info.plist
-rwxr-xr-x      103.0K 2023-05-19 11:07:02 +0000 Interlock
-rw-r--r--          8B 2023-05-16 03:17:32 +0000 PkgInfo
-rw-r--r--      194.7K 2023-05-16 03:17:31 +0000 embedded.mobileprovision
(lldb) ls home
/var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964
drwxr-xr-x         96B 2023-05-19 07:28:01 +0000 Documents
drwxr-xr-x        128B 2023-05-16 04:51:14 +0000 Library
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 SystemData
drwxr-xr-x         64B 2023-05-16 04:51:14 +0000 tmp
(lldb) ls /var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964/Documents
-rw-r--r--         18B 2023-05-16 05:36:05 +0000 report.txt
```

[back to commands list](#Commands-list)



#### find_el - find endless loop

Detects endless loop in all threads at this point.

```objective-c
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    int a = 1;
    NSLog(@"%s", __PRETTY_FUNCTION__);
    while (a) {
        a++;
    }
}
```

```stylus
# touch device screen
2023-05-20 12:29:52.604910+0800 Interlock[56660:1841567] -[ViewController touchesBegan:withEvent:]
# pause program execution, then execute find_el in lldb
(lldb) find_el
Breakpoint 1: where = Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.mm:34:5, address = 0x109dd8d48
Breakpoint 2: where = Interlock`main + 110 at main.m:17:5, address = 0x109dd911e
delete breakpoint 2
call Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.m:34:5, 22 times per second, hit_count: 100
...
```

[back to commands list](#Commands-list)



#### thread_eb - extended backtrace of thread

Get extended backtrace of thread.

```stylus
(lldb) bt
* thread #2, queue = 'com.apple.root.default-qos', stop reason = breakpoint 6.1
  * frame #0: 0x0000000104ab58f8 Concurrency`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000104ab80f8) at ViewController.m:29:13
    frame #1: 0x0000000104df51dc libdispatch.dylib`_dispatch_call_block_and_release + 24
    frame #2: 0x0000000104df519c libdispatch.dylib`_dispatch_client_callout + 16
    frame #3: 0x0000000104e01200 libdispatch.dylib`_dispatch_queue_override_invoke + 968
    frame #4: 0x0000000104e067c8 libdispatch.dylib`_dispatch_root_queue_drain + 604
    frame #5: 0x0000000104e06500 libdispatch.dylib`_dispatch_worker_thread3 + 136
    frame #6: 0x0000000181fc3fac libsystem_pthread.dylib`_pthread_wqthread + 1176
    frame #7: 0x0000000181fc3b08 libsystem_pthread.dylib`start_wqthread + 4

(lldb) thread_eb
thread #4294967295: tid = 0x190c, 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160, queue = 'com.apple.main-thread'
    frame #0: 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160
    frame #1: 0x0000000104ded884 Concurrency`-[ViewController touchesBegan:withEvent:](self=<unavailable>, _cmd=<unavailable>, touches=<unavailable>, event=<unavailable>) at ViewController.m:25:5
    frame #2: 0x000000018bb1583c UIKit`forwardTouchMethod + 340
    frame #3: 0x000000018b9bb760 UIKit`-[UIResponder touchesBegan:withEvent:] + 60
...
```

[back to commands list](#Commands-list)



#### entitlements - dump entitlements

Dump codesign entitlements of the specified module if any.

```stylus
(lldb) ent
Interlock:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>XXXX.com.xxx.Interlock</string>
	<key>com.apple.developer.team-identifier</key>
	<string>XXXX</string>
	<key>com.apple.security.application-groups</key>
	<array/>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>
```

```stylus
(lldb) ent UIKit
UIKit apparently does not contain code signature
```

[back to commands list](#Commands-list)



#### segments - print segments

Print segments and section info of macho.

```stylus
(lldb) segments LLDBCode
[0x4e90000-0x104e90000) 0x100000000 __PAGEZERO ---/---
[0x104e90000-0x104ea0000) 0x10000 __TEXT r-x/r-x
	[0x104e968bc-0x104e9cfb8) 0x66fc __text
	[0x104e9cfb8-0x104e9d210) 0x258 __stubs
	[0x104e9d210-0x104e9d480) 0x270 __stub_helper
	[0x104e9d480-0x104e9db20) 0x6a0 __objc_stubs
	[0x104e9db20-0x104e9edaa) 0x128a __objc_methname
	[0x104e9edaa-0x104e9f2d8) 0x52e __cstring
	[0x104e9f2d8-0x104e9f354) 0x7c __objc_classname__TEXT
	[0x104e9f354-0x104e9fe8e) 0xb3a __objc_methtype
	[0x104e9fe90-0x104e9fe98) 0x8 __const
	[0x104e9fe98-0x104e9ff40) 0xa8 __gcc_except_tab__TEXT
	[0x104e9ff40-0x104e9fff0) 0xb0 __unwind_info
[0x104ea0000-0x104ea4000) 0x4000 __DATA rw-/rw-
	[0x104ea0000-0x104ea0070) 0x70 __got
	[0x104ea0070-0x104ea0200) 0x190 __la_symbol_ptr
	[0x104ea0200-0x104ea0420) 0x220 __const
	[0x104ea0420-0x104ea0ba0) 0x780 __cfstring
	[0x104ea0ba0-0x104ea0bc8) 0x28 __objc_classlist__DATA
	[0x104ea0bc8-0x104ea0be8) 0x20 __objc_protolist__DATA
	[0x104ea0be8-0x104ea0bf0) 0x8 __objc_imageinfo__DATA
	[0x104ea0bf0-0x104ea1f28) 0x1338 __objc_const
	[0x104ea1f28-0x104ea20d8) 0x1b0 __objc_selrefs
	[0x104ea20d8-0x104ea2148) 0x70 __objc_classrefs__DATA
	[0x104ea2148-0x104ea2150) 0x8 __objc_superrefs__DATA
	[0x104ea2150-0x104ea2158) 0x8 __objc_ivar
	[0x104ea2158-0x104ea22e8) 0x190 __objc_data
	[0x104ea22e8-0x104ea2488) 0x1a0 __data
[0x104ea4000-0x104eb0000) 0xc000 __LINKEDIT r--/r--
[0x104eaa510-0x104eaf3e0) 0x4ed0 Code Signature
```

[back to commands list](#Commands-list)



#### main

Print the address of main function.

```stylus
(lldb) main
function main at 0x102911b70(fileoff: 0x5b70)
```

[back to commands list](#Commands-list)



#### executable - print main executable name

Print main executable name.

```stylus
(lldb) executable
LLDBCode
```

[back to commands list](#Commands-list)



#### appdelegate

Find the class that conforms to the UIApplicationDelegate protocol.

```stylus
(lldb) appdelegate
AppDelegate
```

[back to commands list](#Commands-list)



#### classes - print class names 

Print class names in the specified module.

```stylus
(lldb) classes
AppDelegate <0x10468e378>
SceneDelegate <0x10468e418>
ViewController <0x10468e260>
```

[back to commands list](#Commands-list)



#### image_list

List current executable and dependent shared library images, sorted by load address.

```stylus
(lldb) image_list
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
[  1] 0x1022f8000(0x1022f8000) 524.3K /usr/lib/system/introspection/libdispatch.dylib
[  2] 0x1023d0000(0x1023d0000) 163.8K /usr/lib/libsubstitute.dylib
[  3] 0x1023f8000(0x1023f8000)  81.9K /usr/lib/libsubstrate.dylib
...
```

[back to commands list](#Commands-list)



#### slookup - lookup string

Lookup the specified string, between start addr and end addr.

```stylus
(lldb) image_list -c 10
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
[  1] 0x1022f8000(0x1022f8000) 524.3K /usr/lib/system/introspection/libdispatch.dylib
[  2] 0x1023d0000(0x1023d0000) 163.8K /usr/lib/libsubstitute.dylib
[  3] 0x1023f8000(0x1023f8000)  81.9K /usr/lib/libsubstrate.dylib
[  4] 0x10270c000(0x10270c000)   4.5M /usr/lib/substitute-inserter.dylib
[  5] 0x102b54000(0x102b54000)   3.5M /usr/lib/substitute-loader.dylib
[  6] 0x18406f000(0x004044000)   8.7K /usr/lib/libSystem.B.dylib
[  7] 0x184071000(0x004044000) 394.1K /usr/lib/libc++.1.dylib
[  8] 0x1840ca000(0x004044000) 144.7K /usr/lib/libc++abi.dylib
[  9] 0x1840ec000(0x004044000)   8.7M /usr/lib/libobjc.A.dylib
  
(lldb) slookup PROGRAM 0x18406f000 0x184071000
found at 0x184070f7c where = [0x000000018002cf78-0x000000018002cfb8) libSystem.B.dylib.__TEXT.__const
1 locations found

(lldb) x 0x184070f7c -c 64
0x184070f7c: 50 52 4f 47 52 41 4d 3a 53 79 73 74 65 6d 2e 42  PROGRAM:System.B
0x184070f8c: 20 20 50 52 4f 4a 45 43 54 3a 4c 69 62 73 79 73    PROJECT:Libsys
0x184070f9c: 74 65 6d 2d 31 32 35 32 2e 35 30 2e 34 0a 00 00  tem-1252.50.4...
0x184070fac: 00 00 00 00 00 00 00 00 00 92 93 40 01 00 00 00  ...........@....
```

[back to commands list](#Commands-list)



#### blookup - lookup bytes

Lookup the specified bytes in user modules.

```stylus
(lldb) blookup c0 03 5f d6
-----try to lookup bytes in LLDBCode-----
0x104961018
...
0x104969ab8
32 locations found
```

[back to commands list](#Commands-list)



#### patch

Patch bytes in user modules.

```stylus
(lldb) patch c0 03 5f d6
-----try to patch bytes in LLDBCode-----
patch 32 locations
```

[back to commands list](#Commands-list)



#### mtrace - trace module

Trace all functions in the specified module.

```stylus
// begin trace
(lldb) mtrace LLDBCode
-----trace functions in LLDBCode-----
will trace 35 names
begin trace with Breakpoint 1: 35 locations
(lldb) c

// trace log
frame #0: 0x0000000102dd2fb8 LLDBCode`-[ViewController touchesBegan:withEvent:](self=0x00000001d4108040, _cmd="touchesBegan:withEvent:", touches=0x000000015fd0fff0, event=1 element) at ViewController.m:35
frame #0: 0x0000000102dd3a68 LLDBCode`+[MachoTool findMacho](self=0x00000001c0038c40, _cmd="\xc5\xd1K\xb7\xa1A\U00000001") at MachoTool.m:74
frame #0: 0x0000000102dd4318 LLDBCode`__22+[MachoTool findMacho]_block_invoke(.block_descriptor=0x000000015fd0fff0, header_addr=7852818496) at MachoTool.m:110
...
frame #0: 0x0000000102dd5b20 LLDBCode`+[Image findInstruction:](self=0x00000001c0038c40, _cmd="\xc5\xd1K\xb7\xa1A\U00000001", inst_str="śJ\xb7\xa1\U00000005") at Image.m:281
frame #0: 0x0000000102dd32f8 LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4(.block_descriptor=0x00000001c40a5ac0, downloadProgress=0x000000018f903381) at ViewController.m:57
frame #0: 0x0000000102dd3268 LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3(.block_descriptor=0x00000001c40733c0, task=0x00000001c80394e0, error=0x0000000000000000) at ViewController.m:53
frame #0: 0x0000000102dd318c LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000102ec1500) at ViewController.m:45
```

[back to commands list](#Commands-list)



#### bda - breakpoint disable at class

Disable breakpoint(s) at the specified class.

```stylus
(lldb) bda -i ViewController
disable breakpoint 1.8: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:57, address = 0x00000001040e32f8, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.14: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_2 at ViewController.m:50, address = 0x00000001040e31e0, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.18: where = LLDBCode`-[ViewController touchesBegan:withEvent:] at ViewController.m:35, address = 0x00000001040e2fb8, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.20: where = LLDBCode`-[ViewController ls_dir:] at ViewController.m:62, address = 0x00000001040e335c, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.22: where = LLDBCode`-[ViewController viewDidLoad] at ViewController.m:24, address = 0x00000001040e2ec4, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.23: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:53, address = 0x00000001040e3268, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.27: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke at ViewController.m:45, address = 0x00000001040e318c, unresolved, hit count = 1  Options: disabled 

(lldb) bda -i ViewController(extension)
disable breakpoint 1.23: where = LLDBCode`-[ViewController(extension) test] at ViewController.m:20, address = 0x0000000102ec2e7c, unresolved, hit count = 0  Options: disabled 
```

[back to commands list](#Commands-list)



#### dmodule - dump module

Dump the specified module from memory.

```stylus
(lldb) dmodule UIKit
dumping UIKit, this may take a while
ignore __DATA.__bss
ignore __DATA.__common
ignore __DATA_DIRTY.__bss
ignore __DATA_DIRTY.__common
924057600 bytes dump to ~/lldb_dump_macho/UIKit/macho_UIKit
```

> 注意：加载时被修改的数据未恢复

[back to commands list](#Commands-list)



#### dapp - dump App

Dump current iOS App (arm64 only). Typically, dump decrypted ipa from jailbreak device.

```stylus
(lldb) dapp
dumping JITDemo, this may take a while
copy file JITDemo.app/Base.lproj/LaunchScreen.storyboardc/01J-lp-oVM-view-Ze5-6b-2t3.nib
copy file JITDemo.app/Base.lproj/LaunchScreen.storyboardc/UIViewController-01J-lp-oVM.nib
copy file JITDemo.app/Base.lproj/LaunchScreen.storyboardc/Info.plist
copy file JITDemo.app/Base.lproj/Main.storyboardc/UIViewController-BYZ-38-t0r.nib
copy file JITDemo.app/Base.lproj/Main.storyboardc/BYZ-38-t0r-view-8bC-Xf-vdC.nib
copy file JITDemo.app/Base.lproj/Main.storyboardc/Info.plist
copy file JITDemo.app/JITDemo
copy file JITDemo.app/_CodeSignature/CodeResources
copy file JITDemo.app/Frameworks/LLDBJIT.framework/_CodeSignature/CodeResources
copy file JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT
copy file JITDemo.app/Frameworks/LLDBJIT.framework/Info.plist
copy file JITDemo.app/Info.plist
copy file JITDemo.app/PkgInfo
copy file JITDemo.app/embedded.mobileprovision
no file need patch
Generating "JITDemo.ipa"
dump success, ipa path: /Users/xxx/lldb_dump_macho/JITDemo/JITDemo.ipa
```

[back to commands list](#Commands-list)



#### dfile - download file

Download file from home, bundle or group path.

```stylus
(lldb) dfile /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app/Info.plist
dumping Info.plist, this may take a while
1464 bytes written to '/Users/xxx/Info.plist'
```

[back to commands list](#Commands-list)



#### ddir - download directory

Download dir from home, bundle or group path.

```stylus
(lldb) ddir /var/containers/Bundle/Application/7099B2B8-39BE-4204-9BEB-5DF6A75BAA29/JITDemo.app
dumping JITDemo.app, this may take a while
1197 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/LaunchScreen.storyboardc/01J-lp-oVM-view-Ze5-6b-2t3.nib'
896 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/LaunchScreen.storyboardc/UIViewController-01J-lp-oVM.nib'
258 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/LaunchScreen.storyboardc/Info.plist'
916 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/Main.storyboardc/UIViewController-BYZ-38-t0r.nib'
1197 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/Main.storyboardc/BYZ-38-t0r-view-8bC-Xf-vdC.nib'
258 bytes written to '/Users/xxx/JITDemo.app/Base.lproj/Main.storyboardc/Info.plist'
84224 bytes written to '/Users/xxx/JITDemo.app/JITDemo'
4717 bytes written to '/Users/xxx/JITDemo.app/_CodeSignature/CodeResources'
1798 bytes written to '/Users/xxx/JITDemo.app/Frameworks/LLDBJIT.framework/_CodeSignature/CodeResources'
98608 bytes written to '/Users/xxx/JITDemo.app/Frameworks/LLDBJIT.framework/LLDBJIT'
750 bytes written to '/Users/xxx/JITDemo.app/Frameworks/LLDBJIT.framework/Info.plist'
1464 bytes written to '/Users/xxx/JITDemo.app/Info.plist'
8 bytes written to '/Users/xxx/JITDemo.app/PkgInfo'
196731 bytes written to '/Users/xxx/JITDemo.app/embedded.mobileprovision'
```

[back to commands list](#Commands-list)



#### ufile - upload local file to device

Upload local file to the specified directory or path on device.

```stylus
(lldb) doc
/var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
(lldb) ufile /Users/xxx/uploadfile /var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
uploading uploadfile, this may take a while
upload success
(lldb) ufile /Users/xxx/uploadfile /var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents/test
uploading uploadfile, this may take a while
upload success
(lldb) ls doc
/var/mobile/Containers/Data/Application/1171F451-C2DC-47E6-B6E3-74A0FE5A6572/Documents
-rw-r--r--       12.1K 2023-08-10 07:11:29 +0000 test
-rw-r--r--       12.1K 2023-08-10 07:11:22 +0000 uploadfile
```

[back to commands list](#Commands-list)



#### rm - remove file

Remove file or directory on remote device.

```stylus
(lldb) ls doc
/var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents
-rw-r--r--       12.1K 2023-08-10 07:32:05 +0000 test
-rw-r--r--       12.1K 2023-08-10 08:22:40 +0000 uploadfile
(lldb) rm /var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents/uploadfile
remove success
(lldb) ls doc
/var/mobile/Containers/Data/Application/B142040E-B1A0-4E97-8E76-03357585BFF8/Documents
-rw-r--r--       12.1K 2023-08-10 07:32:05 +0000 test
```

[back to commands list](#Commands-list)



#### fblock - find block (arm64 only)

Find the specified block(s) in user modules.

```stylus
(lldb) po $x0
<__NSGlobalBlock__: 0x100f18210>
(lldb) x/4g 0x100f18210
0x100f18210: 0x00000001b57df288 0x0000000050000000
0x100f18220: 0x00000001043b9724 0x00000001043bc1f0
(lldb) info 0x00000001043b9724
0x00000001043b9724,   ___lldb_unnamed_symbol77     <+0> `JITDemo`__TEXT.__text + 0x290

(lldb) fblock 0x100f18210
-----try to lookup block in JITDemo-----
find a block: 0x100f18210 in JITDemo`-[ViewController touchesBegan:withEvent:]
1 block(s) resolved
```

[back to commands list](#Commands-list)



#### blocks - find blocks (arm64 only)

Find blocks in user modules and save block symbols to block_symbol.json

```stylus
(lldb) blocks
-----try to lookup block in JITDemo-----
* using global block var: 0x104a78150 in JITDemo`-[ViewController viewDidLoad] at ViewController.m:39:5
find a block: 0x104a78190 in JITDemo`-[ViewController viewDidLoad] at ViewController.m:0:0
find a block: 0x104a781b0 in JITDemo`-[ViewController touchesBegan:withEvent:] at ViewController.m:0:0
* using global block var: 0x104a78150 in JITDemo`-[ViewController touchesBegan:withEvent:] at ViewController.m:69:5
find a block: 0x104a781f0 in JITDemo`-[ViewController touchesBegan:withEvent:] at ViewController.m:0:0
find a block: 0x104a78230 in JITDemo`-[ViewController touchesBegan:withEvent:] at ViewController.m:0:0
find a stack block @0x104a74e7c in JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:0:0
	stack block func addr 0x104a74f08 JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:75:0
...
-----try to lookup block in LLDBJIT-----
find a block: 0x104b341c0 in LLDBJIT`+[MachoTool findMacho] at MachoTool.m:0:0
find a block: 0x104b34200 in LLDBJIT`+[MachoTool findMacho] at MachoTool.m:0:0
find a block: 0x104b34240 in LLDBJIT`+[Image dumpSegments:] at Image.m:0:0
find a block: 0x104b34280 in LLDBJIT`+[Image dumpApp] at Image.m:0:0
find a stack block @0x104b2f2f4 in LLDBJIT`+[Image removeFile:] at Image.m:0:0
	stack block func addr 0x104b2f788 LLDBJIT`__20+[Image removeFile:]_block_invoke at Image.m:746:0
find a stack block @0x104b2fa3c in LLDBJIT`+[Image dump:slide:regions:] at Image.m:0:0
	stack block func addr 0x104b30008 LLDBJIT`__28+[Image dump:slide:regions:]_block_invoke at Image.m:791:0
find a stack block @0x104b32080 in LLDBJIT`+[Image getBlocksInfo:] at Image.m:0:0
	stack block func addr 0x104b34d40 LLDBJIT`None
85 block(s) resolved
```

[back to commands list](#Commands-list)



#### bblocks - break blocks (arm64 only)

Break all blocks in user modules

```stylus
(lldb) bblocks
-----try to lookup block in JITDemo-----
break block: 0x104a78150 with Breakpoint 4: JITDemo`globalBlock_block_invoke at ViewController.m:16:0, address = 0x104a74990
break block: 0x104a78190 with Breakpoint 5: JITDemo`__29-[ViewController viewDidLoad]_block_invoke at ViewController.m:42:0, address = 0x104a74ac4
break block: 0x104a781b0 with Breakpoint 6: JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke at ViewController.m:63:0, address = 0x104a74d1c
break block: 0x104a781f0 with Breakpoint 7: JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_2 at ViewController.m:72:0, address = 0x104a74d70
break block: 0x104a78230 with Breakpoint 8: JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:74:0, address = 0x104a74df8
find a stack block @0x104a74e7c in JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:0:0
break stack block with Breakpoint 9: JITDemo`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:75:0, address = 0x104a74f08
...
-----try to lookup block in LLDBJIT-----
break block: 0x104b341c0 with Breakpoint 82: LLDBJIT`__22+[MachoTool findMacho]_block_invoke at MachoTool.m:110:0, address = 0x104b2b130
break block: 0x104b34200 with Breakpoint 83: LLDBJIT`__22+[MachoTool findMacho]_block_invoke_2 at MachoTool.m:140:0, address = 0x104b2b2d8
break block: 0x104b34240 with Breakpoint 84: LLDBJIT`__22+[Image dumpSegments:]_block_invoke at Image.m:218:0, address = 0x104b2c724
break block: 0x104b34280 with Breakpoint 85: LLDBJIT`__16+[Image dumpApp]_block_invoke at Image.m:545:0, address = 0x104b2e254
find a stack block @0x104b2f2f4 in LLDBJIT`+[Image removeFile:] at Image.m:0:0
break stack block with Breakpoint 86: LLDBJIT`__20+[Image removeFile:]_block_invoke at Image.m:746:0, address = 0x104b2f788
find a stack block @0x104b2fa3c in LLDBJIT`+[Image dump:slide:regions:] at Image.m:0:0
break stack block with Breakpoint 87: LLDBJIT`__28+[Image dump:slide:regions:]_block_invoke at Image.m:791:0, address = 0x104b30008
find a stack block @0x104b32080 in LLDBJIT`+[Image getBlocksInfo:] at Image.m:0:0
break stack block with Breakpoint 88: LLDBJIT`None, address = 0x104b34d40
set 85 breakpoints
(lldb) 
```

or

```stylus
(lldb) bblocks JITDemo
-----try to lookup block in JITDemo-----
break block: 0x1026ac140 with Breakpoint 87: JITDemo`___lldb_unnamed_symbol75, address = 0x1026a92f4
break block: 0x1026ac180 with Breakpoint 88: JITDemo`___lldb_unnamed_symbol76, address = 0x1026a93e0
break block: 0x1026ac1a0 with Breakpoint 89: JITDemo`___lldb_unnamed_symbol77, address = 0x1026a9534
break block: 0x1026ac1e0 with Breakpoint 90: JITDemo`___lldb_unnamed_symbol78, address = 0x1026a955c
break block: 0x1026ac250 with Breakpoint 91: JITDemo`___lldb_unnamed_symbol82, address = 0x1026a964c
find a stack block @0x1026a95a4 in JITDemo`___lldb_unnamed_symbol78
break stack block with Breakpoint 92: JITDemo`___lldb_unnamed_symbol79, address = 0x1026a9610
find a stack block @0x1026a9694 in JITDemo`___lldb_unnamed_symbol82
break stack block with Breakpoint 93: JITDemo`___lldb_unnamed_symbol83, address = 0x1026a9700
set 7 breakpoints
```

[back to commands list](#Commands-list)



#### initfunc - print mod init func

Dump module init function(s) in user modules.

```stylus
(lldb) initfunc
-----try to lookup init function in JITDemo-----
address = 0x100e08cb0 JITDemo`entry1 at main.m:708:0
address = 0x100e0960c JITDemo`entry2 at main.m:740:0
```

[back to commands list](#Commands-list)



#### binitfunc - break mod init func

Break module init function(s) in user modules.

```stylus
(lldb) binitfunc
-----try to lookup init function in JITDemo-----
Breakpoint 6: JITDemo`entry1 at main.m:708:0, address = 0x100e08cb0
Breakpoint 7: JITDemo`entry2 at main.m:740:0, address = 0x100e0960c
```

[back to commands list](#Commands-list)



#### bmethod - break method

Break the specified method(s) in user modules

```stylus
(lldb) bmethod load
-----try to method in JITDemo-----
Breakpoint 3: JITDemo`+[ViewController load] at ViewController.m:26:0, address = 0x1024f89bc
Breakpoint 4: JITDemo`+[AppDelegate load] at AppDelegate.m:16:0, address = 0x1024f96a4
-----try to method in LLDBJIT-----
set 2 breakpoints
```

[back to commands list](#Commands-list)



#### bmain - break main function

```stylus
(lldb) bmain
Breakpoint 9: BasicSyntax`___lldb_unnamed_symbol266, address = 0x10017c3fc
```

[back to commands list](#Commands-list)



## Credits

https://github.com/DerekSelander/LLDB

https://github.com/facebook/chisel

https://github.com/aaronst/macholibre

## License

YJLLDB is released under the Apache License 2.0. See LICENSE file for details.

