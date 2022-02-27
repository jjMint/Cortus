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
def flattenDataFrame(nestedDataFrame) :
    flattenedDataFrame = nestedDataFrame.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]
    flattenedDataFrame = flattenedDataFrame.T

    return flattenedDataFrame

# --------------------------------------------------------------------------------------------
# // Feature Object
# --------------------------------------------------------------------------------------------
# Class that handles the collation and storage of a dump / processes features
class processObject :
    processName  = None

    headerFeatures      = None
    registryFeatures    = None
    flagFeatures        = None
    sectionFeatures     = None
    entryPointFeatures  = None
    relocationFeatures  = None
    stringsFeatures     = None
    namespaceFeatures   = None
    importFeatures      = None

    def __init__(self, processName):
        self.processName = processName

#--------------------------------------------------------------------------------------------
# Process Setters
#--------------------------------------------------------------------------------------------
    def setHeaderFeatures(self, headerBinFeatures, headerCoreFeatures) :
        self.headerFeatures = pd.concat([headerBinFeatures, headerCoreFeatures], axis=1)
        pprint.pprint(self.headerFeatures)
        
    def setRegistryFeatures(self, registryFeatures) :
        self.registryFeatures = pd.concat([registryFeatures], axis=1)
        pprint.pprint(self.registryFeatures)

    def setFlagFeatures(self, flagFeatures) :
        self.flagFeatures = pd.concat([flagFeatures], axis=1)
        pprint.pprint(self.flagFeatures)

    def setSectionFeatures(self, sectionFeatures) :
        self.sectionFeatures = pd.concat([sectionFeatures], axis=1)
        pprint.pprint(self.sectionFeatures)
        
    def setEntryPointFeatures(self, entryPointFeatures) :
        self.entryPointFeatures = pd.concat([entryPointFeatures], axis=1)
        pprint.pprint(self.entryPointFeatures)
        
    def setRelocationFeatures(self, relocationFeatures) :
        self.relocationFeatures = pd.concat([relocationFeatures], axis=1)
        pprint.pprint(self.relocationFeatures)

    def setStringFeatures(self, stringsFeatures) :
        self.stringsFeatures = pd.concat([stringsFeatures], axis=1)
        pprint.pprint(self.stringsFeatures)

    def setNamespaceFeatures(self, namespaceFeatures) :
        self.namespaceFeatures = pd.concat([namespaceFeatures], axis=1)
        pprint.pprint(self.namespaceFeatures)

    def setImportFeatures(self, importFeatures) :
        self.importFeatures = pd.concat([importFeatures], axis=1)
        pprint.pprint(self.importFeatures)

#--------------------------------------------------------------------------------------------
# Collater functions
#-------------------------------------------------------------------------------------------- 
    def getProcessFeatureTable(self) :
        return None


# --------------------------------------------------------------------------------------------
# // Process Feature Collator
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with collation of features
class featureCollator :
    outputFolder   = None

    def __init__(self, inputFolder, outputFolder):
        self.inputFolder    = inputFolder
        self.outputFolder   = outputFolder

    
# --------------------------------------------------------------------------------------------
# // Memory Feature Extractor
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with containing feature extraction methods
class memoryFeatureExtractor :
    benignInputFolder       = None
    maliciousInputFolder    = None
    benignOutputFolder      = None
    maliciousOutputFolder   = None

    def __init__(self, benignInputFolder, maliciousInputFolder, benignOutputFolder, maliciousOutputFolder):
        self.benignInputFolder       = benignInputFolder
        self.benignOutputFolder      = benignOutputFolder
        self.maliciousInputFolder    = benignInputFolder
        self.maliciousOutputFolder   = benignOutputFolder

        self.extractor(benignInputFolder)

    def extractor(self, inputFolder) :
        inputDirectory        = os.fsencode(inputFolder)
        benignProcessList     = []
        maliciousProcessList  = []

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

            # Collect all relevant feature sets for the process dump
            headerBinFeatures, headerCoreFeatures = self.createHeaderFeatures(r2DumpFile)
            registryFeatures                      = self.createRegisterFeatures(r2DumpFile)
            sectionFeatures                       = self.createSectionFeatures(r2DumpFile)
            flagFeatures                          = self.createFlagFeatures(r2DumpFile)
            entryPointFeatures                    = self.createEntryPointFeatures(r2DumpFile)
            relocationFeatures                    = self.createRelocationFeatures(r2DumpFile)
            stringsFeatures                       = self.createStringFeatures(r2DumpFile)
            namespaceFeatures                     = self.createNamespaceSyscallFeatures(r2DumpFile)
            importFeatures                        = self.createImportsFeatures(r2DumpFile)

            # Create the process object
            process.setHeaderFeatures(headerBinFeatures, headerCoreFeatures)
            process.setRegistryFeatures(registryFeatures)
            process.setSectionFeatures(sectionFeatures)
            process.setFlagFeatures(flagFeatures)
            process.setEntryPointFeatures(entryPointFeatures)
            process.setRelocationFeatures(relocationFeatures)
            process.setStringFeatures(stringsFeatures)
            process.setNamespaceFeatures(namespaceFeatures)
            process.setImportFeatures(importFeatures)

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

        sectionFeaturesNameSize = []
        sectionFeaturesNamePerms = []
        for section in dmpInfo:
            sectionFeaturesNameSize.append({section.get('name'): section.get('size')})
            sectionFeaturesNamePerms.append({section.get('name'): section.get('perm')})

        sectionFeaturesNameSize = flattenDataFrame(pd.DataFrame.from_dict(sectionFeaturesNameSize))
        sectionFeaturesNameSize.columns = ['size']

        sectionFeaturesNamePerms = flattenDataFrame(pd.DataFrame.from_dict(sectionFeaturesNamePerms))
        sectionFeaturesNamePerms.columns = ['perms']

        sectionFeatures = sectionFeaturesNamePerms.join(sectionFeaturesNameSize)
        return sectionFeatures

    def createFlagFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('fsj')
        dmpInfo = json.loads(dmpInfo)

        flagFeatures = pd.DataFrame(dmpInfo)
        return flagFeatures

    def createEntryPointFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('dbtj')
        dmpInfo = json.loads(dmpInfo)

        entryPointFeatures = pd.DataFrame(dmpInfo)
        return entryPointFeatures

    def createRelocationFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('irj')
        dmpInfo = json.loads(dmpInfo)

        relocationFeatures = pd.DataFrame(dmpInfo)
        return relocationFeatures

    def createStringFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('izj')
        dmpInfo = json.loads(dmpInfo)

        stringsFeatures = pd.DataFrame(dmpInfo)
        return stringsFeatures

    def createNamespaceSyscallFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('kj syscall/*')
        dmpInfo = json.loads(dmpInfo)

        # Key short for "analyse"
        namespaceFeatures = pd.DataFrame(dmpInfo['anal'])
        return namespaceFeatures

    def createImportsFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iij')
        dmpInfo = json.loads(dmpInfo)

        importFeatures = pd.DataFrame(dmpInfo)
        return importFeatures

    # Significant parsing work required (later on)
    # def createLibraryFeatures(self, r2DumpFile) :
    #     dmpInfo = r2DumpFile.cmd('ilj')
    #     pprint.pprint(dmpInfo)
    #     return None

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


