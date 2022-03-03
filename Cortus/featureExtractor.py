# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import json
import os
import pandas as pd
import pprint
import r2pipe

from process import Process
from sklearn.feature_extraction import DictVectorizer


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
    benignProcessList     = []
    maliciousProcessList  = []

    def __init__(self, benignInputFolder, maliciousInputFolder, benignOutputFolder, maliciousOutputFolder):
        self.benignInputFolder       = benignInputFolder
        self.benignOutputFolder      = benignOutputFolder
        self.maliciousInputFolder    = benignInputFolder
        self.maliciousOutputFolder   = benignOutputFolder

        self.extractor(benignInputFolder, maliciousInputFolder)

    def extractor(self, benignInputFolder, maliciousInputFolder) :
        benignInputDirectory     = os.fsencode(benignInputFolder)
        maliciousInputDirectory  = os.fsencode(maliciousInputFolder)


        print("-"*50)
        print("Beginning Feature Extraction Process")
        print("Memory Dumps to analyze: " + str(len(os.listdir(benignInputDirectory))))
        print("-"*50)

        for dump in os.listdir(benignInputDirectory) :
            dumpName = os.fsdecode(dump)
            dumpPath = os.path.join(os.fsdecode(benignInputDirectory), dumpName)

            print("-"*50)
            print("Analysing File: " + str(dumpName))
            print("-"*50)

            process = Process("{}_benign".format(dumpName))
            r2DumpFile = r2pipe.open(str(dumpPath))

            # Collect all relevant feature sets for the process dump
            headerFeatures                                      = self.createHeaderFeatures(r2DumpFile)
            registryFeatures                                    = self.createRegisterFeatures(r2DumpFile)
            sectionFeatures                                     = self.createSectionFeatures(r2DumpFile)
            flagFeatures                                        = self.createFlagFeatures(r2DumpFile)
            entryPointFeatures                                  = self.createEntryPointFeatures(r2DumpFile)
            relocationFeatures                                  = self.createRelocationFeatures(r2DumpFile)
            stringsFeatures                                     = self.createStringFeatures(r2DumpFile)
            namespaceFeatures                                   = self.createNamespaceSyscallFeatures(r2DumpFile)
            importFeatures                                      = self.createImportsFeatures(r2DumpFile)

            # Create the process object
            process.setHeaderFeatures(headerFeatures)
            process.setRegistryFeatures(registryFeatures)
            process.setSectionFeatures(sectionFeatures)
            process.setFlagFeatures(flagFeatures)
            process.setEntryPointFeatures(entryPointFeatures)
            process.setRelocationFeatures(relocationFeatures)
            process.setStringFeatures(stringsFeatures)
            process.setNamespaceFeatures(namespaceFeatures)
            process.setImportFeatures(importFeatures)

            pprint.pprint(process.getProcessFeatureTable())

            self.benignProcessList.append(process)
            r2DumpFile.quit()

        # for dump in os.listdir(maliciousInputDirectory) :
        #     dumpName = os.fsdecode(dump)
        #     dumpPath = os.path.join(os.fsdecode(inputDirectory), dumpName)

        #     print("-"*50)
        #     print("Analysing File: " + str(dumpName))
        #     print("-"*50)

        #     process = Process("{}_benign".format(dumpName))
        #     r2DumpFile = r2pipe.open(str(dumpPath))

        #     # Collect all relevant feature sets for the process dump
        #     headerBinFeatures, headerCoreFeatures               = self.createHeaderFeatures(r2DumpFile)
        #     registryFeatures                                    = self.createRegisterFeatures(r2DumpFile)
        #     sectionFeaturesNameSize, sectionFeaturesNamePerms   = self.createSectionFeatures(r2DumpFile)
        #     flagFeatures                                        = self.createFlagFeatures(r2DumpFile)
        #     entryPointFeatures                                  = self.createEntryPointFeatures(r2DumpFile)
        #     (relocationFeaturesName, relocationFeaturesType, 
        #     relocationFeaturesVaddr, relocationFeaturesPaddr, 
        #     relocationFeaturesIsIFunc)                          = self.createRelocationFeatures(r2DumpFile)
        #     (stringsFeaturesOrdinal, stringsFeaturesSize, 
        #     stringsFeaturesLength, stringsFeaturesSection, 
        #     stringsFeaturesType, stringsFeaturesString)         = self.createStringFeatures(r2DumpFile)
        #     namespaceFeatures                                   = self.createNamespaceSyscallFeatures(r2DumpFile)
        #     (importFeaturesOrdinal, importFeaturesType, 
        #     importFeaturesName, importFeaturesLibName)          = self.createImportsFeatures(r2DumpFile)

        #     # Create the process object
        #     process.setHeaderFeatures(headerBinFeatures, headerCoreFeatures)
        #     process.setRegistryFeatures(registryFeatures)
        #     process.setSectionFeatures(sectionFeaturesNameSize, sectionFeaturesNamePerms)
        #     process.setFlagFeatures(flagFeatures)
        #     process.setEntryPointFeatures(entryPointFeatures)
        #     process.setRelocationFeatures(relocationFeaturesName, relocationFeaturesType, relocationFeaturesVaddr, relocationFeaturesPaddr, relocationFeaturesIsIFunc)
        #     process.setStringFeatures(stringsFeaturesOrdinal, stringsFeaturesSize, stringsFeaturesLength, stringsFeaturesSection, stringsFeaturesType, stringsFeaturesString)
        #     process.setNamespaceFeatures(namespaceFeatures)
        #     process.setImportFeatures(importFeaturesOrdinal, importFeaturesType, importFeaturesName, importFeaturesLibName)

        #     pprint.pprint(process.getProcessFeatureTable())

        #     self.maliciousProcessList.append(process)
        #     r2DumpFile.quit()


    def createHeaderFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('ij')
        dmpInfo = json.loads(dmpInfo)

        headerBinFeatures = dmpInfo['bin']
        headerBinFeatures = pd.json_normalize(headerBinFeatures)
        headerCoreFeatures = dmpInfo['core']
        headerCoreFeatures = pd.json_normalize(headerCoreFeatures)

        headerFeatures = pd.concat([headerBinFeatures, headerCoreFeatures], axis=1)
        return headerFeatures


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
        sectionFeaturesNameSize = sectionFeaturesNameSize.T
        sectionFeaturesNameSize = sectionFeaturesNameSize.add_suffix("_size")

        sectionFeaturesNamePerms = flattenDataFrame(pd.DataFrame.from_dict(sectionFeaturesNamePerms))
        sectionFeaturesNamePerms = sectionFeaturesNamePerms.T
        sectionFeaturesNamePerms = sectionFeaturesNamePerms.add_suffix("_perms")

        sectionFeatures = pd.concat([sectionFeaturesNameSize, sectionFeaturesNamePerms], axis=1)
        return sectionFeatures


    def createFlagFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('fsj')
        dmpInfo = json.loads(dmpInfo)

        flagFeatures = pd.DataFrame(dmpInfo)
        flagFeatures = flagFeatures.drop(['selected'], axis=1)
        flagFeatures = flagFeatures.set_index('name')

        flagFeatures = flagFeatures.T.reset_index()
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
        relocationFeatures = relocationFeatures.drop(['demname'], axis=1).T

        relocationFeaturesName    = relocationFeatures.loc[['name']].add_prefix("relocation_name_").reset_index(drop=True)

        relocationFeaturesCount   = pd.DataFrame({'relocationCount':len(pd.DataFrame(dmpInfo).index)}, index=[0])
        print(relocationFeaturesCount)
        print(pd.DataFrame(dmpInfo)['name'].value_counts())

        relocationFeaturesType    = relocationFeatures.loc[['type']].add_prefix("relocation_type_").reset_index(drop=True)
        relocationFeaturesVaddr   = relocationFeatures.loc[['vaddr']].add_prefix("relocation_vaddr_").reset_index(drop=True)
        relocationFeaturesPaddr   = relocationFeatures.loc[['paddr']].add_prefix("relocation_paddr_").reset_index(drop=True)
        relocationFeaturesIsIFunc = relocationFeatures.loc[['is_ifunc']].add_prefix("relocation_isifunc_").reset_index(drop=True)

        relocationFeatures = pd.concat([relocationFeaturesName, relocationFeaturesType, relocationFeaturesVaddr, 
                                        relocationFeaturesPaddr, relocationFeaturesIsIFunc], axis=1)
        return relocationFeatures


    def createStringFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('izj')
        dmpInfo = json.loads(dmpInfo)

        stringsFeatures = pd.DataFrame(dmpInfo).drop(['blocks', 'paddr', 'vaddr'], axis=1)

        stringsFeaturesCount = pd.DataFrame({'stringCount':len(stringsFeatures.index)}, index=[0])
        print(stringsFeaturesCount)


        stringsFeatures = stringsFeatures[stringsFeatures['size'] > 50].reset_index(drop=True)
        print(stringsFeatures['string'].value_counts())

        stringsFeatures = stringsFeatures[stringsFeatures['size'] > 50].reset_index(drop=True).T
        stringsFeaturesOrdinal = stringsFeatures.loc[['ordinal']].add_prefix("string_ordinal_").reset_index(drop=True)
        stringsFeaturesSize    = stringsFeatures.loc[['size']].add_prefix("string_size_").reset_index(drop=True)
        stringsFeaturesLength  = stringsFeatures.loc[['length']].add_prefix("string_length_").reset_index(drop=True)
        stringsFeaturesSection = stringsFeatures.loc[['section']].add_prefix("string_section_").reset_index(drop=True)
        stringsFeaturesType    = stringsFeatures.loc[['type']].add_prefix("string_type_").reset_index(drop=True)
        stringsFeaturesString  = stringsFeatures.loc[['string']].add_prefix("string_string_").reset_index(drop=True)

        stringsFeatures = pd.concat([stringsFeaturesOrdinal, stringsFeaturesSize, stringsFeaturesLength, 
                                    stringsFeaturesSection, stringsFeaturesType, stringsFeaturesString], axis=1)
        return stringsFeatures


    def createNamespaceSyscallFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('kj syscall/*')
        dmpInfo = json.loads(dmpInfo)
        # Key short for "analyse"
        namespaceFeatures = pd.DataFrame(dmpInfo['anal']).T.reset_index(drop=True)

        namespaceFeaturesCount = pd.DataFrame({'syscallCount':len(pd.DataFrame(dmpInfo['anal']).reset_index(drop=True).index)}, index=[0])
        print(namespaceFeaturesCount)

        namespaceFeatures = namespaceFeatures.add_prefix("syscall_")
        namespaceFeatures = namespaceFeatures.iloc[: , 1:]
        return namespaceFeatures


    def createImportsFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iij')
        dmpInfo = json.loads(dmpInfo)

        importFeatures = pd.DataFrame(dmpInfo).drop(['bind', 'plt'], axis=1)

        importFeaturesCount = pd.DataFrame({'importCount':len(importFeatures.index)}, index=[0])
        print(importFeaturesCount)

        print(importFeatures['name'].value_counts())
        print(importFeatures['libname'].value_counts())

        importFeaturesOrdinal = importFeatures.T.loc[['ordinal']].add_prefix("import_ordinal_").reset_index(drop=True)
        importFeaturesType    = importFeatures.T.loc[['type']].add_prefix("string_type_").reset_index(drop=True)
        importFeaturesName    = importFeatures.T.loc[['name']].add_prefix("string_name_").reset_index(drop=True)
        importFeaturesLibName = importFeatures.T.loc[['libname']].add_prefix("string_libname_").reset_index(drop=True)

        importFeatures = pd.concat([importFeaturesOrdinal, importFeaturesType, importFeaturesName, 
                                    importFeaturesLibName], axis=1)
        return importFeatures