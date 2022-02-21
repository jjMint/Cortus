# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor used as a form of EDA for the wider machine learning model
# Focuses on the creation of usable and quantifiable data derived through the use of radare2 on process memory dumps
# ------------------------------------------------------------------------------------------------------------------

import getopt
import json
import os
import pandas as pd
import pprint
import r2pipe
import sys
import typing

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------
# // Feature Object
# ---------------------------
# Class that handles the collation and storage of a dump / processes features
class processObject :
    processName: str  = None

    headerFeatures    = None
    sectionFeatures   = None
    registerFeatures  = None
    flagFeatures      = None
    stringsFeatures   = None

    def __init__(self, processName):
        self.processName = processName

    def setHeaderFeatures(self, headerBinFeatures, headerCoreFeatures) :
        self.headerFeatures = pd.concat([headerBinFeatures, headerCoreFeatures], axis=1)
        # pprint.pprint(self.headerFeatures)
        
    def setRegistryFeatures(self, registryFeatures) :
        self.registryFeatures = pd.concat([registryFeatures], axis=1)
        # pprint.pprint(self.registryFeatures)

    def setFlagFeatures(self, flagFeatures) :
        self.flagFeatures = pd.concat([flagFeatures], axis=1)
        # pprint.pprint(self.flagFeatures)

    def setSectionFeatures(self, sectionFeatures) :
        self.sectionFeatures = pd.concat([sectionFeatures], axis=1)
        # pprint.pprint(self.sectionFeatures)
        
# --------------------------------------------------------------------------------------------
# // Process Feature Collator
# ---------------------------
# Class that handles input and output pathing along with collation of features
class featureCollator :
    outputFolder: str   = None

    def __init__(self, inputFolder, outputFolder):
        self.inputFolder    = inputFolder
        self.outputFolder   = outputFolder

    
# --------------------------------------------------------------------------------------------
# // Memory Feature Extractor
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with containing feature extraction methods
class memoryFeatureExtractor :
    benignInputFolder:     str   = None
    maliciousInputFolder:  str   = None
    benignOutputFolder:    str   = None
    maliciousOutputFolder: str   = None

    def __init__(self, benignInputFolder, maliciousInputFolder, benignOutputFolder, maliciousOutputFolder):
        self.benignInputFolder: str      = benignInputFolder
        self.benignOutputFolder: str     = benignOutputFolder
        self.maliciousInputFolder: str   = benignInputFolder
        self.maliciousOutputFolder: str  = benignOutputFolder

        self.extractor(benignInputFolder)

    def extractor(self, inputFolder) :
        inputDirectory: str        = os.fsencode(inputFolder)
        benignProcessList: list    = []
        maliciousProcessList: list = []

        print("-"*50)
        print("Beginning Feature Extraction Process")
        print("Memory Dumps to analyze: " + str(len(os.listdir(inputDirectory))))
        print("-"*50)

        for dump in os.listdir(inputDirectory) :
            dumpName = os.fsdecode(dump)
            dumpPath = os.path.join(os.fsdecode(inputDirectory), dumpName)

            print("-"*50)
            print("Analysing File: " + str(dumpName))
            print("-"*50)

            process = processObject(dumpName)
            r2DumpFile = r2pipe.open(str(dumpPath))

            headerBinFeatures, headerCoreFeatures = self.createHeaderFeatures(r2DumpFile)
            registryFeatures = self.createRegisterFeatures(r2DumpFile)
            sectionFeatures = self.createSectionFeatures(r2DumpFile)
            flagFeatures = self.createFlagFeatures(r2DumpFile)
            otherFeatures = self.createOtherFeatures(r2DumpFile)
            
            process.setHeaderFeatures(headerBinFeatures, headerCoreFeatures)
            process.setRegistryFeatures(registryFeatures)
            process.setSectionFeatures(sectionFeatures)
            process.setFlagFeatures(flagFeatures)

            benignProcessList.append(process)

            r2DumpFile.quit()


    def createHeaderFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('ij')
        dmpInfo = json.loads(dmpInfo)

        headerBinFeatures = dmpInfo['bin']
        headerBinFeatures = pd.json_normalize(headerBinFeatures)
        headerCoreFeatures = dmpInfo['core']
        headerCoreFeatures = pd.json_normalize(headerCoreFeatures)

        return headerBinFeatures, headerCoreFeatures


    def createRegisterFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('drj')
        dmpInfo = json.loads(dmpInfo)

        registryFeatures = dmpInfo
        registryFeatures = pd.json_normalize(registryFeatures)

        return registryFeatures
    
    # Module and sections result in same data
    def createSectionFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iSj')
        dmpInfo = json.loads(dmpInfo)

        # Add in permissions per section
        # dmpInfo = r2DumpFile.cmd('omj')
        # dmpInfo = json.loads(dmpInfo)
        # pprint.pprint(dmpInfo)

        sectionFeaturesNameSize = []
        for section in dmpInfo:
            sectionFeaturesNameSize.append({section.get('name'): section.get('size')})

        sectionFeaturesNameSize = pd.DataFrame.from_dict(sectionFeaturesNameSize)
        sectionFeaturesNameSize = sectionFeaturesNameSize.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]
        sectionFeaturesNameSize = sectionFeaturesNameSize.T
        sectionFeaturesNameSize.columns = ['size']

        return sectionFeaturesNameSize

    def createFlagFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('fsj')
        dmpInfo = json.loads(dmpInfo)

        flagFeatures = []
        for flag in dmpInfo[1:]:
            flagFeatures.append({flag.get('name'): flag.get('count')})
        flagFeatures = pd.DataFrame.from_dict(flagFeatures)
        flagFeatures = flagFeatures.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]

        return flagFeatures


    def createOtherFeatures(self, r2DumpFile) :
        # Useful other features (for review)
        # dmpInfo = r2DumpFile.cmd('dbtj')
        # dmpInfo = r2DumpFile.cmd('ir')
        # dmpInfo = r2DumpFile.cmd('iz')
        # dmpInfo = r2DumpFile.cmd('iij')
        # dmpInfo = r2DumpFile.cmd('ie')
        # dmpInfo = r2DumpFile.cmd('iI')

        # dmpInfo = json.loads(dmpInfo)
        print(dmpInfo)
        # pprint.pprint(dmpInfo)

        # return flagFeatures

def main(argv) :
    benignInputFolder      = None
    maliciousInputFolder   = None
    benignOutputFolder     = None
    maliciousOutputFolder  = None

    try :
        opts, args = getopt.getopt(argv, "hi:o", ["iBenignFolder=", "oBenignFolder=", "iMaliciousFolder=", "oMaliciousFolder="])
    except getopt.GetoptError :
        print("Please provide and input and ouput folder location: featureExtractor.py -i <inputBenignFolder> -o <outputBenignFolder> -b <inputMaliciousFolder> -g <outputMaliciousFolder>")
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-h':
            print("featureExtractor.py -i <inputBenignFolder> -o <outputBenignFolder> -b <inputMaliciousFolder> -g <outputMaliciousFolder>")
            sys.exit()
        elif opt in ("-i", "--iBenignFolder"):
            benignInputFolder = arg
        elif opt in ("-o", "--oBenignFolder"):
            benignOutputFolder = arg
        elif opt in ("-b", "--iMaliciousFolder"):
            maliciousInputFolder = arg
        elif opt in ("-g", "--oMaliciousFolder"):
            maliciousOutputFolder = arg

    featureExtractor = memoryFeatureExtractor(benignInputFolder, benignOutputFolder, maliciousInputFolder, maliciousOutputFolder)

if __name__ == "__main__":
    main(sys.argv[1:])


