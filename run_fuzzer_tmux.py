'''
    Author:
        Yi Yang
    
    Time:
        2020/07/09
    
    Description:
    
    Log:
    
        2020/07/09
        Add restart mode, clean output and re-compile program before running.
 
'''
import argparse
import json
import time
from multiprocessing import Pool, Manager
import threading
import random

import CommonLib

global g_root_directory
global g_file_name
global g_running_mode
global g_fuzzer_name
global g_timeout

if __name__ == '__main__':
    global g_root_directory
    global g_file_name
    global g_running_mode
    global g_fuzzer_name
    global g_timeout

    parser = argparse.ArgumentParser()
    parser.add_argument ("-r", "--root_path", type=str, required=True, help="Current project path.")
    parser.add_argument ("-n", "--file_name", type=str, required=True, help="Name of the executable file.")
    parser.add_argument ("-m", "--mode", type=str, required=True, help="Running mode.")
    parser.add_argument ("-f", "--fuzzer", type=str, required=True, help="fuzzzer name.")
    parser.add_argument ("-t", "--timeout", type=str, required=True, help="time out.")
    
    args = parser.parse_args ()
    if args.root_path :
        g_root_directory = args.root_path
        print(args.root_path)
    if args.file_name :
        g_file_name = args.file_name
        print(args.file_name)
    if args.mode :
        g_running_mode = args.mode
        print(args.mode)
    if args.fuzzer :
        g_fuzzer_name = args.fuzzer
        print(args.fuzzer)
    if args.timeout :
        g_timeout = args.timeout
        print(args.timeout)
 
    if g_running_mode == "restart":
        print("init")
        CommonLib.initialize_output_directory(g_root_directory, g_file_name)
        
    elif g_running_mode == "full_restart":
        CommonLib.recompile_fuzzer()
        CommonLib.initialize_output_directory( g_file_name)
        print("recompile")
    
    if "AFL++" == g_fuzzer_name:
        if "cxxfilt" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 15, 2)
        elif "xmllint" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "readpng" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "guetzli-2017-3-30-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "json-2017-02-12-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libpng-1.2.56-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libxml2-v2.9.2-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "freetype2-2017-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "harfbuzz-1.3.2-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libjpeg-turbo-07-2017-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libpng2-1.2.56-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "openssl-1.0.2d-binary" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        else:
            print("Wrong target program of AFL++")

    elif "AFL" == g_fuzzer_name:
        if "cxxfilt" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 15, 2)
        elif "xmllint" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "readpng" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "guetzli-2017-3-30-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "json-2017-02-12-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libpng-1.2.56-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libxml2-v2.9.2-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "freetype2-2017-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "harfbuzz-1.3.2-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libjpeg-turbo-07-2017-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        elif "libpng2-1.2.56-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)        
        elif "openssl-1.0.2d-binary" == g_file_name:
            CommonLib.run_afl_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        else:
            print("Wrong target program of AFL")

    elif "QSYM" == g_fuzzer_name:
        if "cxxfilt" == g_file_name:
            CommonLib.run_qsym_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 15, 2)
        elif "xmllint" == g_file_name:
            CommonLib.run_qsym_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        else:
            print("Wrong target program of AFL++")

    elif "SYMQEMU" == g_fuzzer_name:
        if "cxxfilt" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 15, 2)
        elif "xmllint" == g_file_name:
            CommonLib.run_aflplusplus_fuzzer_tmux(g_root_directory, g_file_name, g_timeout, 10, 3)
        else:
            print("Wrong target program of AFL")
    
