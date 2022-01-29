# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor used as a form of EDA for the wider machine learning model
# Focuses on the creation of usable and quantifiable data derived through the use of radare2 on process memory dumps

import getopt
import os
import pandas
import r2pipe
import sys

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------
# // Feature Object
# ---------------------------
# Class that handles the collation and storage of a dump / processes features
class processObject :

    processName  = None

    headerFeatures    = None
    memoryMapFeatures = None
    registerFeatures  = None
    heapFeatures      = None
    flagFeatures      = None
    moduleFeatures    = None


    def __init__(self, processName):
        self.processName = processName

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

        self.extractor(benignInputFolder)

    def extractor(self, inputFolder) :
        inputDirectory = os.fsencode(inputFolder)

        print("-"*50)
        print("Beginning Feature Extraction Process")
        print("Memory Dumps to analyze: " + str(len(os.listdir(inputDirectory))))
        print("-"*50)

        for dump in os.listdir(inputDirectory) :
            dumpName = os.fsdecode(dump)
            print("-"*50)
            print("Analysing File: " + str(dumpName))
            print("-"*50)
            r2DumpFile = r2pipe.open(dumpName)
            r2DumpFile.quit()


    def createHeaderFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('ij')

        return None

    def createMemoryMapFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('dmj')

        return None

    def createRegisterFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('drj')

        return None
    
    def createHeapFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('dmhj')

        return None

    def createSectionFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iSj')

        return None

    def createFlagFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('fsj')

        return None
    
    def createModuleFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iSqj')

        return None


def main(argv) :
    benignInputFolder      = None
    maliciousInputFolder   = None
    benignOutputFolder     = None
    maliciousOutputFolder  = None


    try :
        opts, args = getopt.getopt(argv, "hi:o", ["iBenignFolder=", "oBenignFolder=", "iMaliciousFolder=", "oMaliciousFolder="])
    except getopt.GetoptError :
        print("Please provide and input and ouput folder location: featureExtractor.py -bi <inputBenignFolder> -bo <outputBenignFolder> -mi <inputMaliciousFolder> -mo <outputMaliciousFolder>")
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-h':
            print("featureExtractor.py -bi <inputBenignFolder> -bo <outputBenignFolder> -mi <inputMaliciousFolder> -mo <outputMaliciousFolder>")
            sys.exit()
        elif opt in ("-i", "--iBenignFolder"):
            benignInputFolder = arg
        elif opt in ("-o", "--oBenignFolder"):
            benignOutputFolder = arg
        elif opt in ("-mi", "--iMaliciousFolder"):
            maliciousInputFolder = arg
        elif opt in ("-mo", "--oMaliciousFolder"):
            maliciousOutputFolder = arg

    featureExtractor = memoryFeatureExtractor(benignInputFolder, benignOutputFolder, maliciousInputFolder, maliciousOutputFolder)

if __name__ == "__main__":
    main(sys.argv[1:])


