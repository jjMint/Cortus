# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor used as a form of EDA for the wider machine learning model
# Focuses on the creation of usable and quantifiable data derived through the use of radare2 on process memory dumps

import r2pipe
import os

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------
# // Feature Object
# ---------------------------
# Class that handles the collation and storage of a dump / processes features
class featureCollator :

    inputFolder     = None
    outputFolder    = None

    def __init__(self, inputFolder, outputFolder):
        self.inputFolder    = inputFolder
        self.outputFolder   = outputFolder


# --------------------------------------------------------------------------------------------
# // Feature Collator
# ---------------------------
# Class that handles input and output pathing along with collation of features
class featureCollator :

    inputFolder     = None
    outputFolder    = None

    def __init__(self, inputFolder, outputFolder):
        self.inputFolder    = inputFolder
        self.outputFolder   = outputFolder

    
# --------------------------------------------------------------------------------------------
# // Memory Feature Extractor
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with containing feature extraction methods
class memoryFeatureExtractor :

    benignInputFolder      = None
    maliciousInputFolder   = None
    benignOutputFolder     = None
    maliciousOutputFolder  = None

    def __init__(self, benignInputFolder, maliciousInputFolder, benignOutputFolder, maliciousOutputFolder):
        self.benignInputFolder       = benignInputFolder
        self.benignOutputFolder      = benignOutputFolder
        self.maliciousInputFolder    = benignInputFolder
        self.maliciousOutputFolder   = benignOutputFolder

    def extractor(self) :
        inputDirectory = os.fsencode(self.inputFolder)

        print("-"*50)
        print("Beginning Feature Extraction Process")
        print("Memory Dumps to analyze: " len(os.listdir(inputDirectory)))
        print("-"*50)

        for dump in os.listdir(inputDirectory) :
            dumpName = os.fsdecode(dump)
            r2DumpFile = r2pipe.open("dumpName")


    def headerFeatures(self) :
        return None

    def memoryMapFeatures(self) :
        return None

    def registerFeatures(self) :
        return None
    
    def heapFeatures(self) :
        return None

    def sectionFeatures(self) :
        return None

    def flagFeatures(self) :
        return None
    
    def moduleFeatures(self) :
        return None
    

# Initial File Opening (Will need to make this flexible for each file and handle errors)
r2 = r2pipe.open("../../../Desktop/notepad.exe_220121_221437.dmp")

dmpInfo = print(r2.cmd('ij'))
# dmpMemoryMap = print(r2.cmd('dmj'))
# dmpRegisters = print(r2.cmd('drj'))
# dmpHeap = print(r2.cmd('dmhj'))
# dmpSections = print(r2.cmd('iSj'))
dmpFlags = print(r2.cmd('fsj'))
dmpModules = print(r2.cmd('iSqj'))

r2.quit()
