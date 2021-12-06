import argparse
import networkx as nx
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
# cxxfilt start

def run_cxxfilt_fuzzer_terminal(root_directory, program_name, id):
	
	afl_path            = os.path.join(root_directory, "..", "AFLplusplus", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join("/mnt", "ssd", "output", program_name, id)
	program_path        = os.path.join(root_directory, "target_bin", program_name)

	cmd_line = "gnome-terminal --geometry=400x400 -- bash -c"
	cmd_line = cmd_line + " " + "\'"
	cmd_line = cmd_line + afl_path
	cmd_line = cmd_line + " -i " + input_directory
	cmd_line = cmd_line + " -o " + output_directory
	cmd_line = cmd_line + " -M " + "Master" + id
	cmd_line = cmd_line + " -Q "
	cmd_line = cmd_line + " -m none "
	cmd_line = cmd_line + " -p FAST "
	cmd_line = cmd_line + " -P 30 "  
	cmd_line = cmd_line + " " + program_path + "\'"

	print(cmd_line)
	os.system(cmd_line)

'''
FunctionName:
	get_directed_fuzzer_tmux_command

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
def get_directed_fuzzer_tmux_command(root_directory, program_name, type, power_schedule, step, task_id, process_id):
	afl_path            = os.path.join(root_directory, "AFLplusplus_Directed", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join("/mnt", "ssd", "output", program_name, str(task_id))
	#output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
	#program_binary_name = get_program_binary_name(program_name)
	program_binary_name = program_name
	program_path        = os.path.join(root_directory, "target_bin", program_binary_name)

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
	cmd_line = cmd_line + " -p " + power_schedule
	cmd_line = cmd_line + " -P " + str(step)
	cmd_line = cmd_line + " -q " + "original_queue"
	cmd_line = cmd_line + " " + program_path

	#print(cmd_line)
	return cmd_line

def run_cxxfilt_directed_fuzzer_tmux(root_directory, program_name, timeout, task_count, process_count):
	tmux_name = "DirectedFuzzer"
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
				fuzz_cmd_line = get_directed_fuzzer_tmux_command(root_directory, program_name, "Master", "DEPTH_FIRST", 30, i, j)
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
				fuzz_cmd_line = get_directed_fuzzer_tmux_command(root_directory, program_name, "Slave", "DEPTH_FIRST", 30, i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_directed_fuzzer_tmux_command(root_directory, program_name, "Slave", "DEPTH_FIRST", 30,  i, j)
				fuzz_cmd_line = "timeout " + timeout + " " + fuzz_cmd_line

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")


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
	afl_path            = os.path.join(root_directory, "..", "..","DirectedFuzzer_test","AFLplusplus", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join("/mnt", "ssd", "output", program_name, str(task_id))
	#output_directory    = os.path.join(root_directory, "output", program_name, str(task_id))
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
	run_cxxfilt_aflplusplus_fuzzer_tmux

Argument:
	root_directory
	program_name
	task_count
	process_count

Result:
	None

Comment:

'''
def run_aflplusplus_fuzzer_tmux(root_directory, program_name, timeout, task_count, process_count):
	tmux_name = "DirectedFuzzer"
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
def get_afl_tmux_command(root_directory, program_name, type, power_schedule, step, task_id, process_id):
	afl_path            = os.path.join(root_directory, "..", "afl-2.52b", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join("/mnt", "ssd", "output", program_name, str(task_id))
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
	cmd_line = cmd_line + " -p " + power_schedule
	cmd_line = cmd_line + " -P " + str(step)
	cmd_line = cmd_line + " " + program_path

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
def run_afl_fuzzer_tmux(root_directory, program_name, task_count, process_count):
	tmux_name = "DirectedFuzzer-" + program_name
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
				fuzz_cmd_line = get_aflplusplus_tmux_command(root_directory, program_name, "Master", "FAST", 30, i, j)
				#print(fuzz_cmd_line)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

			elif 2 == j:
				# symbolic execution
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_aflplusplus_tmux_command(root_directory, program_name, "Slave", "FAST", 30, i, j)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_aflplusplus_tmux_command(root_directory, program_name, "Slave", "FAST", 30,  i, j)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")

# cxxfilt end
#######################################################################################################################################

#######################################################################################################################################
# QSYM end

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
def get_qsym_tmux_command(root_directory, program_name, type, power_schedule, step, task_id, process_id):
	afl_path            = os.path.join(root_directory, "..", "afl-2.52b", "afl-fuzz")
	input_directory     = os.path.join(root_directory, "input", program_name, "in")
	output_directory    = os.path.join("mnt", "ssd", "output", program_name, str(task_id))
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
	cmd_line = cmd_line + " -p " + power_schedule
	cmd_line = cmd_line + " -P " + str(step)
	cmd_line = cmd_line + " " + program_path

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
def run_qsym_tmux(root_directory, program_name, task_count, process_count):
	tmux_name = "DirectedFuzzer-" + program_name
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
				fuzz_cmd_line = get_aflplusplus_tmux_command(root_directory, program_name, "Master", "FAST", 30, i, j)
				#print(fuzz_cmd_line)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

			elif 2 == j:
				# symbolic execution
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = get_aflplusplus_tmux_command(root_directory, program_name, "Slave", "FAST", 30, i, j)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)
			
			else:
				# other slave
				cmd_line = ""
				fuzz_cmd_line = ""
				fuzz_cmd_line = cmd_line + get_aflplusplus_tmux_command(root_directory, program_name, "Slave", "FAST", 30,  i, j)

				cmd_line = "tmux send-keys -t %s 'tmux select-window -t %s && tmux select-pane -t %d && %s' ENTER;" % (tmux_name, current_window_name, j + 1, fuzz_cmd_line)
				print(cmd_line)
				os.system(cmd_line)
				time.sleep(0.3)

	print("[run_cxxfilt_fuzzer_tmux] ........ ok")

# QSYM end
#######################################################################################################################################



#######################################################################################################################################
# Directed Fuzzer start

'''
FunctionName:
	initialize_directed_symqemu_output_directory

Argument:
	root_directory
	exe_file_name

Result:
	None

Comment:
	
'''
def initialize_directed_symqemu_output_directory(root_directory, exe_file_name):
	symqemu_output_directory = os.path.join("/mnt","ssd", "output", exe_file_name, "symqemu")
	if os.path.exists(symqemu_output_directory):
		shutil.rmtree(symqemu_output_directory)
	
	os.makedirs(symqemu_output_directory)
	os.mkdir(os.path.join(symqemu_output_directory,"queue"))
	os.mkdir(os.path.join(symqemu_output_directory,"dependency"))
	os.mkdir(os.path.join(symqemu_output_directory,"status"))
	
	# create status files
	write_data = struct.pack("<l",-1)

	status_file_path = os.path.join(symqemu_output_directory,"status","afl-master_sync_index")
	outfile = open(status_file_path,'wb')
	outfile.write(write_data)
	outfile.close()

	status_file_path = os.path.join(symqemu_output_directory,"status","afl-slave_sync_index")
	outfile = open(status_file_path,'wb')
	outfile.write(write_data)
	outfile.close()

	write_data = struct.pack("<l",0)
	status_file_path = os.path.join(symqemu_output_directory,"status","output_index")
	outfile = open(status_file_path,'wb')
	outfile.write(write_data)
	outfile.close()

'''
FunctionName:
	run_qsym

Argument:
	root_directory
	exe_file_name
	program_misc
	seed_file_path

Result:
	None

Comment:

'''
def run_directed_symqemu(root_directory,exe_file_name,program_misc,seed_path,monitor_type):
	pin_path				= os.path.join(root_directory, "third_party","pin-2.14-71313-gcc.4.4.7-linux","pin.sh")
	pin_misc				= " -injection child -ifeellucky "
	qsym_path				= os.path.join(root_directory, "cdg_qsym_simple","pintool","obj-intel64","libqsym.so")

	#qsym_misc				= " -d 1 -f 1 -debug_subsumption 1 "
	qsym_misc				= " -f 1 "
	log_path				= os.path.join(root_directory, "log", exe_file_name + ".log")
	output_path				= os.path.join(root_directory, "output", exe_file_name, "afl-cdg-simple", "defective")
	bitmap_path				= os.path.join(output_path,"qsym_bitmap")
	program_path			= os.path.join(root_directory, "target_bin", exe_file_name)
	
	edge_black_list_path	= os.path.join(root_directory, "input", exe_file_name, exe_file_name + "_EdgeBlackList.json")

	print(seed_path)

	if monitor_type == "stdin":
		stdin_monitor_cmd_line = []
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + [pin_path,"-injection", "child", "-ifeellucky"]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-t",qsym_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-s","1"]
		#cmd_line = cmd_line + ["-d","1"]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-logfile", log_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-i", seed_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-b", bitmap_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-o", output_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["-edge_black_list", edge_black_list_path]
		stdin_monitor_cmd_line = stdin_monitor_cmd_line + ["--",program_path]
		#cmd_line = cmd_line + [program_misc]
		
		print(stdin_monitor_cmd_line)
		temp = ""
		for current_s in stdin_monitor_cmd_line:
			temp = temp + " " + current_s
		print(temp)
		#os.system(cmd_line)
		with open(seed_path, "rb") as f:
			file_content = f.read()
			f.close()
		print(file_content)

		with open(os.devnull, "wb") as devnull:
			proc = sp.Popen(stdin_monitor_cmd_line, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
			stdout, stderr = proc.communicate(file_content)
			#print(stderr.decode("utf-8") + "\n")
			#print(stdout.decode("utf-8") + "\n")
	elif monitor_type == "file":
		file_monitor_cmd_line = pin_path + pin_misc
		file_monitor_cmd_line = file_monitor_cmd_line + " -t " + qsym_path
		file_monitor_cmd_line = file_monitor_cmd_line + qsym_misc
		file_monitor_cmd_line = file_monitor_cmd_line + " -logfile " + log_path
		file_monitor_cmd_line = file_monitor_cmd_line + " -i " + seed_path
		file_monitor_cmd_line = file_monitor_cmd_line + " -b " + bitmap_path
		file_monitor_cmd_line = file_monitor_cmd_line + " -o " + output_path
		file_monitor_cmd_line = file_monitor_cmd_line + " -edge_black_list " + edge_black_list_path
		file_monitor_cmd_line = file_monitor_cmd_line + " -- " + program_path
		file_monitor_cmd_line = file_monitor_cmd_line + " " + program_misc
		file_monitor_cmd_line = file_monitor_cmd_line + " " + seed_path
		print(file_monitor_cmd_line)
		os.system(file_monitor_cmd_line)



# Directed Fuzzer end
#######################################################################################################################################