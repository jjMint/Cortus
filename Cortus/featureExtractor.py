# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import json
import os
import pandas as pd
import r2pipe

from process import Process

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------
def flattenDataFrame(nestedDataFrame) :
    flattenedDataFrame = nestedDataFrame.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]
    flattenedDataFrame = flattenedDataFrame.T

    return flattenedDataFrame


# --------------------------------------------------------------------------------------------
# // Memory Feature Extractor
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with containing feature extraction methods
class MemoryFeatureExtractor :
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

            process = Process("{}_benign".format(dumpName))
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

        sectionFeatures = sectionFeaturesNamePerms.join(sectionFeaturesNameSize).T
        return sectionFeatures

    def createFlagFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('fsj')
        dmpInfo = json.loads(dmpInfo)

        flagFeatures = pd.DataFrame(dmpInfo)
        flagFeatures = flagFeatures.drop(['selected'], axis=1)
        flagFeatures = flagFeatures.set_index('name')

        flagFeatures = flagFeatures.T.reset_index(drop=True)
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

        stringsFeatures = pd.DataFrame(dmpInfo).drop(['blocks', 'paddr', 'vaddr'], axis=1)
        return stringsFeatures

    def createNamespaceSyscallFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('kj syscall/*')
        dmpInfo = json.loads(dmpInfo)

        # Key short for "analyse"
        namespaceFeatures = pd.DataFrame(dmpInfo['anal']).T.reset_index(drop=True)
        return namespaceFeatures

    def createImportsFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iij')
        dmpInfo = json.loads(dmpInfo)

        importFeatures = pd.DataFrame(dmpInfo).drop(['bind', 'plt'], axis=1)
        return importFeatures