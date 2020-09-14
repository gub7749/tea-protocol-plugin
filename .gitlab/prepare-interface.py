from os import path
import os
import shutil
import sys
import subprocess

rootPath = path.abspath(path.join(path.dirname(path.abspath(__file__)), ".."))
teaProtocolPath = path.join(rootPath, "teaProtocol")

# move all into teaProtocol

if not path.isdir(teaProtocolPath):
	os.makedirs(teaProtocolPath)

for filename in os.listdir(rootPath):
	filePath = path.join(rootPath, filename)
	if filePath.endswith("teaProtocol"):
		continue
	shutil.move(filePath, path.join(teaProtocolPath, filename))

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

# move teaProtocol to plugins

shutil.move(teaProtocolPath, path.join(rootPath, "plugins", "teaProtocol"))