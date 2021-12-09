import argparse
import re
import os
import sys
import json
import shutil
import time
import struct

import global_var

#######################################################################################################################################
# global start

def get_program_binary_name(program_name):
	result_name = ""
	if program_name in global_var.cxxfilt_cves:
		result_name = global_var.cxxfilt_binary_name
	else:
		result_name = program_name

	return result_name

def get_tmux_window_name(program_name):
	if program_name in global_var.cxxfilt_cves:
		return global_var.cxxfilt_window_name

	if "cxxfilt" == program_name:
		return global_var.cxxfilt_window_name
	elif "xmllint" == program_name:
		return global_var.libxml2_window_name
	elif "libpng" == program_name:
		return global_var.libpng_window_name
	elif "guetzli-2017-3-30-binary" == program_name:
		return global_var.guetzli_window_name
	elif "json-2017-02-12-binary" == program_name:
		return global_var.json_window_name
	elif "libpng-1.2.56-binary" == program_name:
		return global_var.libpng_window_name
	elif "libxml2-v2.9.2-binary" == program_name:
		return global_var.libxml2_window_name
	elif "freetype2-2017-binary" == program_name:
		return global_var.freetype_window_name
	elif "harfbuzz-1.3.2-binary" == program_name:
		return global_var.harfbuzz_window_name
	elif "libjpeg-turbo-07-2017-binary" == program_name:
		return global_var.libjpeg_window_name
	elif "libpng2-1.2.56-binary" == program_name:
		return global_var.libpng_window_name
	elif "openssl-1.0.2d-binary" == program_name:
		return global_var.openssl102d_window_name
	
	print("[clean_output_directory] ........ ok")
	
	return None

def get_input_type(program_name):
	if "cxxfilt" == program_name:
		return global_var.cxxfilt_monitor_type
	elif "xmllint" == program_name:
		return global_var.libxml2_monitor_type
	elif "libpng" == program_name:
		return global_var.libpng_monitor_type
	elif "guetzli-2017-3-30-binary" == program_name:
		return global_var.guetzli_monitor_type
	elif "json-2017-02-12-binary" == program_name:
		return global_var.json_monitor_type
	elif "libpng-1.2.56-binary" == program_name:
		return global_var.libpng_monitor_type
	elif "libxml2-v2.9.2-binary" == program_name:
		return global_var.libxml2_monitor_type
	elif "freetype2-2017-binary" == program_name:
		return global_var.freetype_monitor_type
	elif "harfbuzz-1.3.2-binary" == program_name:
		return global_var.harfbuzz_monitor_type
	elif "libjpeg-turbo-07-2017-binary" == program_name:
		return global_var.libjpeg_monitor_type
	elif "libpng2-1.2.56-binary" == program_name:
		return global_var.libpng_monitor_type
	elif "openssl-1.0.2d-binary" == program_name:
		return global_var.openssl102d_monitor_type
	
	print("[clean_output_directory] ........ ok")
	
	return None

def recompile_fuzzer(root_directory, program_name):
	aflplusplus_directory	= os.path.join(root_directory, "..", "AFLplusplus")
	qemuafl_directory		= os.path.join(aflplusplus_directory, "qemu_mode")

	os.chdir(aflplusplus_directory)
	os.system("make clean")
	os.system("make")

	os.chdir(qemuafl_directory)
	os.system("./build_qemu_support.sh")

	print("[recompile_fuzzer] ........ ok")


def initialize_output_directory(root_directory,program_name):
	print("initialize fuzz output directory")

	output_directory = os.path.join(root_directory,"output", program_name)
	if os.path.exists(output_directory):
		shutil.rmtree(output_directory)
	
	os.makedirs(output_directory)
		
	
	print("[clean_output_directory] ........ ok")


# global end
#######################################################################################################################################

#######################################################################################################################################
# aflplusplus start

'''
FunctionName:
	get_aflplusplus_tmux_command

Argument:
	root_directory
	program_name
	power_schedule
	step
	task_id
	process_id

Result:
	cmd_line

Comment:
	One deterministic fuzzer and One undeterministic fuzzer

'''
def get_aflplusplus_tmux_command(root_directory, program_name, type, task_id, process_id):
	afl_path            = os.path.join(root_directory, "AFLplusplus", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
	program_path        = os.path.join(root_directory, "target_bin", program_name)

	input_type			= get_input_type(program_name)
	if None == input_type:
		return -1

	cmd_line = ""
	cmd_line = cmd_line + afl_path
	cmd_line = cmd_line + " -i " + input_directory
	cmd_line = cmd_line + " -o " + output_directory
	if "Master" == type:
		cmd_line = cmd_line + " -M " + "Master" + str(process_id)
		cmd_line = cmd_line + " -D "
	elif "Slave" == type:
		cmd_line = cmd_line + " -S " + "Slave" + str(process_id)
	cmd_line = cmd_line + " -Q "
	cmd_line = cmd_line + " -m none "
	cmd_line = cmd_line + " " + program_path
	if "file" == input_type:
		cmd_line = cmd_line + " @@"

	#print(cmd_line)
	return cmd_line

'''
FunctionName:
	run_aflplusplus_fuzzer_tmux

Argument:
	root_directory
	program_name
	timeout
	task_count
	process_count

Result:
	None

Comment:

'''
def run_aflplusplus_fuzzer_tmux(root_directory, program_name, timeout, task_count, process_count):
	tmux_name = program_name
	cmd_line = ""

	for i in range(0, task_count):
		# init directory
		output_directory = os.path.join(root_directory, "output", program_name, str(i))
		print(output_directory)

		if os.path.exists(output_directory):
			shutil.rmtree(output_directory)

		os.makedirs(output_directory)

		# start tmux
		current_window_name = get_tmux_window_name(program_name) + "_" + str(i)
		cmd_line ="tmux send-keys -t %s 'tmux new-window -n %s' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -v' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -U' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t 0' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		current_window_name = get_tmux_window_name(program_name) + "_" + str(i)
		for j in range(0, process_count):
			print("current i:%d \tj:%d" % ( i, j ))
			if 0 == j:
				# master
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_aflplusplus_tmux_command(root_directory, program_name, "Master", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line
				#print(fuzz_cmd_line)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_aflplusplus_tmux_command(root_directory, program_name, "Slave", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")

# aflplusplus end
#######################################################################################################################################

#######################################################################################################################################
# afl-qemu start

'''
FunctionName:
	get_aflplusplus_tmux_command

Argument:
	root_directory
	program_name
	power_schedule
	step
	task_id
	process_id

Result:
	cmd_line

Comment:

'''
def get_afl_tmux_command(root_directory, program_name, type, task_id, process_id):
	afl_path            = os.path.join(root_directory, "afl-2.52b", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
	program_path        = os.path.join(root_directory, "target_bin", program_name)

	cmd_line = ""
	cmd_line = cmd_line + afl_path
	cmd_line = cmd_line + " -i " + input_directory
	cmd_line = cmd_line + " -o " + output_directory
	if "Master" == type:
		cmd_line = cmd_line + " -M " + "Master" + str(process_id)
	elif "Slave" == type:
		cmd_line = cmd_line + " -S " + "Slave" + str(process_id)
	cmd_line = cmd_line + " -Q "
	cmd_line = cmd_line + " -m none "
	cmd_line = cmd_line + " -- " + program_path

	#print(cmd_line)
	return cmd_line

'''
FunctionName:
	run_cxxfilt_afl_fuzzer_tmux

Argument:
	root_directory
	program_name
	task_count
	process_count

Result:


Comment:

'''
def run_afl_fuzzer_tmux(root_directory, program_name, timeout, task_count, process_count):
	tmux_name = program_name
	cmd_line = ""

	for i in range(0, task_count):
		# init directory
		output_directory = os.path.join(root_directory, "output", program_name, str(i))
		print(output_directory)

		if os.path.exists(output_directory):
			shutil.rmtree(output_directory)

		os.makedirs(output_directory)

		# start tmux
		current_window_name = program_name + "_" + str(i)
		cmd_line ="tmux send-keys -t %s 'tmux new-window -n %s' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -v' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -U' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t 0' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		current_window_name = program_name + "_" + str(i)
		for j in range(0, process_count):
			print("current i:%d \tj:%d" % ( i, j ))
			if 0 == j:
				# master
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_afl_tmux_command(root_directory, program_name, "Master", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line
				#print(fuzz_cmd_line)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

			elif 2 == j:
				# symbolic execution
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_afl_tmux_command(root_directory, program_name, "Slave", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_afl_tmux_command(root_directory, program_name, "Slave", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line
				
				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")

# # afl-qemu end
#######################################################################################################################################

#######################################################################################################################################
# QSYM start

'''
FunctionName:
	get_aflplusplus_tmux_command

Argument:
	root_directory					
	program_name					program name
	type							Master or Slave
	task_id
	process_id

Result:
	cmd_line

Comment:

'''
def get_qsym_tmux_afl_command(root_directory, program_name, type, task_id, process_id):
	afl_path            = os.path.join(root_directory, "afl-2.52b", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
	program_path        = os.path.join(root_directory, "target_bin", program_name)
	input_type			= get_input_type(program_name)

	cmd_line = ""
	cmd_line = cmd_line + afl_path
	cmd_line = cmd_line + " -i " + input_directory
	cmd_line = cmd_line + " -o " + output_directory
	if "Master" == type:
		cmd_line = cmd_line + " -M " + "Master" + str(process_id)
	elif "Slave" == type:
		cmd_line = cmd_line + " -S " + "Slave" + str(process_id)
	cmd_line = cmd_line + " -Q "
	cmd_line = cmd_line + " -m none "
	if "file" == input_type:
		print("file")
		cmd_line = cmd_line + " -- " + program_path + " @@"
	elif "stdin" == input_type:
		print("stdin")
		cmd_line = cmd_line + " -- " + program_path

	#print(cmd_line)
	return cmd_line

'''
FunctionName:
	get_aflplusplus_tmux_command

Argument:
	root_directory
	program_name
	power_schedule
	step
	task_id
	process_id

Result:
	cmd_line

Comment:
	bin/run_qsym_afl.py -a afl-slave -o $OUTPUT -n qsym -- $QSYM_CMDLINE

'''
def get_qsym_tmux_pintool_command(root_directory, program_name, task_id, process_id ):
	qsym_script_path    = os.path.join(root_directory, "qsym", "bin", "run_qsym_afl.py")
	output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
	program_path        = os.path.join(root_directory, "target_bin", program_name)
	input_type			= get_input_type(program_name)

	cmd_line = ""
	cmd_line = cmd_line + qsym_script_path
	cmd_line = cmd_line + " -o " + output_directory
	cmd_line = cmd_line + " -a " + "Slave" + str(process_id)
	cmd_line = cmd_line + " -n qsym " + output_directory
	cmd_line = cmd_line + " -- " + program_path
	
	if "file" == input_type:
		print("file")

	elif "stdin" == input_type:
		print("stdin")

	#print(cmd_line)
	return cmd_line

'''
FunctionName:
	run_cxxfilt_afl_fuzzer_tmux

Argument:
	root_directory
	program_name
	task_count
	process_count

Result:


Comment:

'''
def run_qsym_fuzzer_tmux(root_directory, program_name, timeout, task_count, process_count):
	tmux_name = program_name
	cmd_line = ""

	for i in range(0, task_count):
		# init directory
		output_directory = os.path.join(root_directory, "output", program_name, str(i))
		print(output_directory)

		if os.path.exists(output_directory):
			shutil.rmtree(output_directory)

		os.makedirs(output_directory)

		# start tmux
		current_window_name = program_name + "_" + str(i)
		cmd_line ="tmux send-keys -t %s 'tmux new-window -n %s' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -v' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -U' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux split-window -h' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)

		cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t 0' ENTER;" % (tmux_name, current_window_name)
		print(cmd_line)
		os.system(cmd_line)
		time.sleep(0.3)
		
		current_window_name = program_name + "_" + str(i)
		for j in range(0, process_count):
			print("current i:%d \tj:%d" % ( i, j ))
			if 0 == j:
				# master
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_qsym_tmux_afl_command(root_directory, program_name, "Master", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line
				#print(fuzz_cmd_line)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

			elif 2 == j:
				# symbolic execution
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_qsym_tmux_afl_command(root_directory, program_name, i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_qsym_tmux_pintool_command(root_directory, program_name, "Slave", i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")

# QSYM end
#######################################################################################################################################
