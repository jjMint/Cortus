# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import json
import logging
import numpy as np
import os
import pandas as pd
import pprint
import r2pipe
import sys

from process import Process

logging.basicConfig(level=logging.INFO)

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------
def flattenDataFrame(nestedDataFrame) :
    flattenedDataFrame = nestedDataFrame.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]
    flattenedDataFrame = flattenedDataFrame.T

    return flattenedDataFrame

def blockPrint():
    sys.stdout = open(os.devnull, 'w')

def enablePrint():
    sys.stdout = sys.__stdout__


# --------------------------------------------------------------------------------------------
# // Memory Feature Extractor
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with containing feature extraction methods
class MemoryFeatureExtractor :
    benignInputFolder       = None
    maliciousInputFolder    = None
    benignOutputFolder      = None
    maliciousOutputFolder   = None


    def __init__(self, benignInputFolder, maliciousInputFolder, benignOutputFolder, maliciousOutputFolder) :
        self.benignInputFolder       = benignInputFolder
        self.benignOutputFolder      = benignOutputFolder
        self.maliciousInputFolder    = benignInputFolder
        self.maliciousOutputFolder   = benignOutputFolder

        self.extractor(benignInputFolder, benignOutputFolder, maliciousInputFolder, maliciousOutputFolder)


    def createProcessList(self, inputFolder, outputFolder, processType) :
        logging.info("-"*50)
        logging.info("Begining {} Feature Extraction Process".format(processType))
        logging.info("Memory Dumps to analyze: " + str(len(os.listdir(inputFolder))))
        logging.info("-"*50)

        for dump in os.listdir(inputFolder) :
            dumpName = os.fsdecode(dump)
            dumpPath = os.path.join(os.fsdecode(inputFolder), dumpName)
            logging.info("Analysing File: " + str(dumpName))

            process = Process("{}_{}".format(dumpName, processType), processType)
            try :
                r2DumpFile = r2pipe.open(str(dumpPath))
            except :
                logging.error("Failed to extract features from file: {}".format(dumpName))

            # Collect all relevant feature sets for the process dump
            # -------------------------------------------------------------------------------------
            # Due to the nature of the memory dumps, its entirely possible that the dump is missing
            # components we are trying to extract, as such we need to "try", during testing only the header results in this occuring

            try :
                headerFeatures                                  = self.createHeaderFeatures(r2DumpFile)
            except:
                logging.warning("Failed to extract header features")
                continue
            registryFeatures                                    = self.createRegisterFeatures(r2DumpFile)
            sectionFeatures                                     = self.createSectionFeatures(r2DumpFile)
            flagFeatures                                        = self.createFlagFeatures(r2DumpFile)
            entryPointFeatures                                  = self.createEntryPointFeatures(r2DumpFile)
            relocationFeatures                                  = self.createRelocationFeatures(r2DumpFile)
            stringsFeatures                                     = self.createStringFeatures(r2DumpFile)
            importFeatures                                      = self.createImportsFeatures(r2DumpFile)
            slackFeatures                                       = self.createSlackFeatures(r2DumpFile)

            # Create the process object
            process.setHeaderFeatures(headerFeatures)
            process.setRegistryFeatures(registryFeatures)
            process.setSectionFeatures(sectionFeatures)
            process.setFlagFeatures(flagFeatures)
            process.setEntryPointFeatures(entryPointFeatures)
            process.setRelocationFeatures(relocationFeatures)
            process.setStringFeatures(stringsFeatures)
            process.setImportFeatures(importFeatures)
            process.setSlackFeatures(slackFeatures)

            process.getProcessFeatureTable().to_csv(os.path.join(os.fsdecode(outputFolder), dumpName.replace('dmp', 'csv')), index=False)
            r2DumpFile.quit()


    def extractor(self, benignInputFolder, benignOutputDirectory, maliciousInputFolder, maliciousOutputDirectory) :
        benignInputDirectory     = os.fsencode(benignInputFolder)
        maliciousInputDirectory  = os.fsencode(maliciousInputFolder)
        benignOutputDirectory    = os.fsencode(benignOutputDirectory)
        maliciousOutputDirectory = os.fsencode(maliciousOutputDirectory)

        self.createProcessList(benignInputDirectory, benignOutputDirectory, 'benign')
        self.createProcessList(maliciousInputDirectory, maliciousOutputDirectory, 'malicious')


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
        relocationFeaturesCount   = pd.DataFrame({'relocationCount':len(pd.DataFrame(dmpInfo).index)}, index=[0])
        # relocationValueCounts = relocationFeatures.loc['name'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("count_").reset_index(drop=True)

        relocationContent = relocationFeatures.loc['name'].tolist()
        relocationContent = {"relocationContent":[relocationContent]}
        relocationContentFrame = pd.DataFrame(relocationContent)
        
        relocationFeatures = pd.concat([relocationContentFrame, relocationFeaturesCount], axis=1)
        return relocationFeatures


    def createStringFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('izj')
        dmpInfo = json.loads(dmpInfo)

        stringsFeatures = pd.DataFrame(dmpInfo).drop(['blocks', 'paddr', 'vaddr'], axis=1)

        stringsFeaturesCount = pd.DataFrame({'stringCount':len(stringsFeatures.index)}, index=[0])
        # stringsValueCount = stringsFeatures['string'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("stringcount_").reset_index(drop=True)
        # stringsSectionValueCount = stringsFeatures['section'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("sectionstringcount_").reset_index(drop=True)
        stringsTypeValueCount = stringsFeatures['type'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("sectiontypecount_").reset_index(drop=True)

        # Here we want to create a list of all the strings per process so we can use TFIDF as a feature component in the wider models
        stringContent = stringsFeatures.loc['string'].tolist()
        stringContent = {"stringContentFull":[stringContent]}
        stringContentFrame = pd.DataFrame(stringContent)
        
        sectionContent = stringsFeatures.loc['section'].tolist()
        stringContent = {"sectionContentFull":[sectionContent]}
        sectionContentFrame = pd.DataFrame(sectionContent)

        stringsFeatures = pd.concat([sectionContentFrame, stringContentFrame, stringsTypeValueCount, stringsFeaturesCount, stringContentFrame], axis=1)
        return stringsFeatures


    def createImportsFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('iij')
        dmpInfo = json.loads(dmpInfo)

        importFeatures = pd.DataFrame(dmpInfo).drop(['bind', 'plt'], axis=1)

        importFeaturesCount = pd.DataFrame({'importCount':len(importFeatures.index)}, index=[0])
        # importFeaturesNameValueCount = importFeatures['name'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("count_").reset_index(drop=True)
        # importFeaturesLibNameValueCount = importFeatures['libname'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("count_").reset_index(drop=True)

        importNameContent = importFeatures['name'].tolist()
        importNameContent = {"importNameContentFull":[importNameContent]}
        importNameContentFrame = pd.DataFrame(importNameContent)
  
        importLibContent = importFeatures['libname'].tolist()
        importLibContent = {"importLibContentFull":[importLibContent]}
        importLibContentFrame = pd.DataFrame(importLibContent)
        
        importFeatures = pd.concat([importNameContentFrame, importLibContentFrame, importFeaturesCount], axis=1)
        return importFeatures

    
    def createSlackFeatures(self, r2DumpFile) :
        dmpInfo = r2DumpFile.cmd('/xj 90')
        dmpInfo = json.loads(dmpInfo)

        slackFeatures = pd.DataFrame(dmpInfo)
        slackFeatureCounts = len(slackFeatures.index)
        slackCountsFrame = pd.DataFrame({"slackByteCount":[slackFeatureCounts]})

        return slackCountsFrame
