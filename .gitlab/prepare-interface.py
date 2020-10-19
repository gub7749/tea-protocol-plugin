from os import path
import os
import shutil
import sys
import subprocess

rootPath = path.abspath(path.join(path.dirname(path.abspath(__file__)), ".."))
teaProtocolPluginPath = path.join(rootPath, "tea-protocol-plugin")

# move all into tea-protocol-plugin

if not path.isdir(teaProtocolPluginPath):
	os.makedirs(teaProtocolPluginPath)

for filename in os.listdir(rootPath):
	filePath = path.join(rootPath, filename)
	if filePath.endswith("tea-protocol-plugin"):
		continue
	shutil.move(filePath, path.join(teaProtocolPluginPath, filename))

# git clone interface

def run(processArgs):
	process = subprocess.Popen(
	    processArgs.split(" "),
	    stdout=sys.stdout,
	    stderr=sys.stderr,
	    cwd=rootPath
	)
	process.wait()

run("git init")
run("git remote add origin https://git.tivolicloud.com/tivolicloud/interface")
run("git fetch")
run("git branch master origin/master")
run("git checkout -f master")

# move tea-protocol-plugin to plugins

shutil.move(teaProtocolPluginPath, path.join(rootPath, "plugins", "tea-protocol-plugin"))