import logging
import glob
import time
import os

log.info("Trying process: " + str(self.pid))

procdump_exe = os.path.abspath(os.path.join("bin", "procdump.exe"))
subprocess.Popen(procdump_exe + " -ma {}".format(self.pid, shell = True))
time.sleep(5)

dumpedProcesses = set()

dump_file = glob.glob(os.getcwd()+"\\*.dmp")
log.info(dump_file)

for file in dump_file:
    if file not in dumpedProcesses:
        dumpedProcesses.add(file)
        upload_to_host(file, os.path.join("file", file))
    else:
        log.info("Process: " + self.pid + " already dumped")
