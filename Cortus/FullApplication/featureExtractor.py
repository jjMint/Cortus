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
import threading
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


    def __init__(self, inputFolder, outputFolder, processType) :
        self.bulkExtractor(inputFolder, outputFolder, processType)


    def callback(loop, callback_event):
        print("Stopping loop")
        loop.stop()
        callback_event.set()


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
            except Exception as e:
                print(e)
                logging.error("Failed to extract features from file: {}".format(dumpName))

            # Collect all relevant feature sets for the process dump
            # -------------------------------------------------------------------------------------
            # Due to the nature of the memory dumps, its entirely possible that the dump is missing
            # components we are trying to extract, as such we need to "try", during testing only the header results in this occuring

            try :
                headerFeatures                                  = self.createHeaderFeatures(r2DumpFile)
            except:
                logging.warning("Failed to extract header features")
                pass
            # registryFeatures                                    = self.createRegisterFeatures(r2DumpFile)
            sectionFeatures                                     = self.createSectionFeatures(r2DumpFile)
            flagFeatures                                        = self.createFlagFeatures(r2DumpFile)
            entryPointFeatures                                  = self.createEntryPointFeatures(r2DumpFile)
            relocationFeatures                                  = self.createRelocationFeatures(r2DumpFile)
            stringsFeatures                                     = self.createStringFeatures(r2DumpFile)
            importFeatures                                      = self.createImportsFeatures(r2DumpFile)
            slackFeatures                                       = self.createSlackFeatures(r2DumpFile)

            # Create the process object per dump and write to to disk
            try :
                process.setHeaderFeatures(headerFeatures)
                # process.setRegistryFeatures(registryFeatures)
                process.setSectionFeatures(sectionFeatures)
                process.setFlagFeatures(flagFeatures)
                process.setEntryPointFeatures(entryPointFeatures)
                process.setRelocationFeatures(relocationFeatures)
                process.setStringFeatures(stringsFeatures)
                process.setImportFeatures(importFeatures)
                process.setSlackFeatures(slackFeatures)
            except :
                logging.warning("Failed to set a feature for the analysed proccess, could be reduction in quality")


            process.getProcessFeatureTable().to_csv(os.path.join(os.fsdecode(outputFolder), dumpName.replace('dmp', 'csv')), index=False)
            r2DumpFile.quit()


    def singleExtractor(self, file, outputDirectory, type) :
        self.createProcessList(file, outputDirectory, type)
        

    def bulkExtractor(self, inputFolder, outputFolder, processType) :
        inputFolder   = os.fsencode(inputFolder)
        outputFolder  = os.fsencode(outputFolder)
        self.createProcessList(inputFolder, outputFolder, processType)


    def createHeaderFeatures(self, r2DumpFile) :
        dmpInfoHeader = r2DumpFile.cmdj('ij')

        headerBinFeatures = dmpInfoHeader['bin']
        headerBinFeatures = pd.json_normalize(headerBinFeatures)
        headerCoreFeatures = dmpInfoHeader['core']
        headerCoreFeatures = pd.json_normalize(headerCoreFeatures)

        headerFeatures = pd.concat([headerBinFeatures, headerCoreFeatures], axis=1)
        return headerFeatures


    def createRegisterFeatures(self, r2DumpFile) :
        dmpInfoReg = r2DumpFile.cmdj('drj')

        registryFeatures = dmpInfoReg
        registryFeatures = pd.json_normalize(registryFeatures)
        return registryFeatures
    

    # Module and sections result in same data
    def createSectionFeatures(self, r2DumpFile) :
        dmpInfoSection = r2DumpFile.cmdj('iSj')

        sectionFeaturesNameSize      = []
        sectionFeaturesNamePerms     = []
        sectionFeaturesNameSizeList  = []
        sectionFeaturesNamePermsList = []
        print(dmpInfoSection)
        for section in dmpInfoSection:
            sectionFeaturesNameSize.append({section.get('name'): section.get('size')})
            sectionFeaturesNamePerms.append({section.get('name'): section.get('perm')})
            sectionFeaturesNameSize.append(section.get('name') + '_' + str(section.get('size')))
            sectionFeaturesNamePerms.append(section.get('name') + '_' + str(section.get('perm')))

        sectionFeaturesNameSize = flattenDataFrame(pd.DataFrame.from_dict(sectionFeaturesNameSize))
        sectionFeaturesNameSize = sectionFeaturesNameSize.T
        sectionFeaturesNameSize = sectionFeaturesNameSize.add_suffix("_size")

        sectionFeaturesNamePerms = flattenDataFrame(pd.DataFrame.from_dict(sectionFeaturesNamePerms))
        sectionFeaturesNamePerms = sectionFeaturesNamePerms.T
        sectionFeaturesNamePerms = sectionFeaturesNamePerms.add_suffix("_perms")

        sectionFeaturesNameSizeContent = {"sectionNameSizeContentFull":sectionFeaturesNameSizeList}
        sectionFeaturesNameSizeContentFrame = pd.DataFrame(sectionFeaturesNameSizeContent)
        sectionFeaturesNamePermsContent = {"sectionNamePermsContentFull":sectionFeaturesNamePermsList}
        sectionFeaturesNamePermsFrame = pd.DataFrame(sectionFeaturesNamePermsContent)

        sectionFeatures = pd.concat([sectionFeaturesNameSize, sectionFeaturesNamePerms, sectionFeaturesNameSizeContentFrame, sectionFeaturesNamePermsFrame], axis=1)
        return sectionFeatures


    def createFlagFeatures(self, r2DumpFile) :
        dmpInfoFlag = r2DumpFile.cmdj('fsj')

        flagFeatures = pd.DataFrame(dmpInfoFlag)
        flagFeatures = flagFeatures.drop(['selected'], axis=1)
        flagFeatures = flagFeatures.set_index('name')
        flagFeatures = flagFeatures.T.reset_index()
        return flagFeatures


    def createEntryPointFeatures(self, r2DumpFile) :
        dmpInfoEp = r2DumpFile.cmdj('dbtj')

        entryPointFeatures = pd.DataFrame(dmpInfoEp)
        return entryPointFeatures


    def createRelocationFeatures(self, r2DumpFile) :
        dmpInfoReloc = r2DumpFile.cmdj('irj')

        relocationFeatures = pd.DataFrame(dmpInfoReloc)
        relocationFeatures = relocationFeatures.drop(['demname'], axis=1).T
        relocationFeaturesCount   = pd.DataFrame({'relocationCount':len(pd.DataFrame(dmpInfoReloc).index)}, index=[0])

        relocationContent = relocationFeatures.loc['name'].tolist()
        relocationContent = {"relocationContent":[relocationContent]}
        relocationContentFrame = pd.DataFrame(relocationContent)
        relocationFeatures = pd.concat([relocationContentFrame, relocationFeaturesCount], axis=1)
        return relocationFeatures


    def createStringFeatures(self, r2DumpFile) :
        dmpInfoStrings = r2DumpFile.cmdj('izj')

        stringsFeatures = pd.DataFrame(dmpInfoStrings).drop(['blocks', 'paddr', 'vaddr'], axis=1)
        stringsTypeValueCount = stringsFeatures['type'].value_counts().rename_axis('unique_values').reset_index(name='counts').set_index('unique_values').T.add_prefix("sectiontypecount_").reset_index(drop=True)

        # Here we want to create a list of all the strings per process so we can perform LSH per process 
        stringContent = stringsFeatures.loc['string'].tolist()
        stringContent = {"stringContentFull":[stringContent]}
        stringContentFrame = pd.DataFrame(stringContent)
        sectionContent = stringsFeatures.loc['section'].tolist()
        stringContent = {"sectionContentFull":[sectionContent]}
        sectionContentFrame = pd.DataFrame(sectionContent)

        stringsFeatures = pd.concat([stringsTypeValueCount, sectionContentFrame, stringContentFrame], axis=1)
        return stringsFeatures


    def createImportsFeatures(self, r2DumpFile) :
        dmpInfoImp = r2DumpFile.cmdj('iij')

        importFeatures = pd.DataFrame(dmpInfoImp).drop(['bind', 'plt'], axis=1)
        importFeaturesCount = pd.DataFrame({'importCount':len(importFeatures.index)}, index=[0])

        importNameContent = importFeatures['name'].tolist()
        importNameContent = {"importNameContentFull":[importNameContent]}
        importNameContentFrame = pd.DataFrame(importNameContent)
        importLibContent = importFeatures['libname'].tolist()
        importLibContent = {"importLibContentFull":[importLibContent]}
        importLibContentFrame = pd.DataFrame(importLibContent)
        
        importFeatures = pd.concat([importNameContentFrame, importLibContentFrame, importFeaturesCount], axis=1)
        return importFeatures

    
    def createSlackFeatures(self, r2DumpFile) :
        dmpInfoSlack = r2DumpFile.cmdj('/xj 90')

        slackFeatures = pd.DataFrame(dmpInfoSlack)
        slackFeatureCounts = len(slackFeatures.index)
        slackCountsFrame = pd.DataFrame({"slackByteCount":[slackFeatureCounts]})
        return slackCountsFrame
