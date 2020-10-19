from os import path
import os
import re
import shutil
import sys
import subprocess
import tarfile
import urllib.request

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

# download and extract interface

print("Downloading interface...")
interfaceArchivePath = path.join(rootPath, "interface.tar.gz")
urllib.request.urlretrieve(
    "https://git.tivolicloud.com/tivolicloud/interface/-/archive/master/interface-master.tar.gz",
    interfaceArchivePath
)

print("Extracting interface...")
with tarfile.open(interfaceArchivePath, "r:gz") as archive:
	for file in archive.getmembers():
		file.name = re.sub(r"^interface-master/", "", file.name)
		archive.extract(file, rootPath)
os.remove(interfaceArchivePath)

# move tea-protocol-plugin to plugins

shutil.move(
    teaProtocolPluginPath,
    path.join(rootPath, "plugins", "tea-protocol-plugin")
)
