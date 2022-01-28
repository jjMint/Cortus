import r2pipe

# Initial File Opening (Will need to make this flexible for each file and handle errors)
r2 = r2pipe.open("./notepad.exe_220121_221437.dmp")

dmpInfo = print(r2.cmd('ij'))
dmpMemoryMap = print(r2.cmd('dmj'))
dmpRegisters = print(r2.cmd('drj'))
dmpHeap = print(r2.cmd('dmhj'))
dmpSections = print(r2.cmd('iSj'))
dmpFlags = print(r2.cmd('fsj'))
dmpModules = print(r2.cmd('iSqj'))

r2.quit()
