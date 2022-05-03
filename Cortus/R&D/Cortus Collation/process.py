# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import logging
import pandas as pd

logging.basicConfig(level=logging.INFO)

# --------------------------------------------------------------------------------------------
# // Process Object
# --------------------------------------------------------------------------------------------
# Class that handles the collation and storage of a dump / processes features
class Process :
    processName         = None
    processType         = None
    headerFeatures      = None
    registryFeatures    = None
    flagFeatures        = None
    sectionFeatures     = None
    entryPointFeatures  = None
    relocationFeatures  = None
    stringsFeatures     = None
    namespaceFeatures   = None
    importFeatures      = None
    slackFeatures       = None

    def __init__(self, processName, processType):
        self.processName = processName
        self.processType = processType

#--------------------------------------------------------------------------------------------
# Process Setters
#--------------------------------------------------------------------------------------------
    def setHeaderFeatures(self, headerFeatures) :
        self.headerFeatures = headerFeatures
        logging.debug(self.headerFeatures)
        
    def setRegistryFeatures(self, registryFeatures) :
        self.registryFeatures = registryFeatures
        logging.debug(self.registryFeatures)

    def setFlagFeatures(self, flagFeatures) :
        self.flagFeatures = flagFeatures
        logging.debug(self.flagFeatures)

    def setSectionFeatures(self, sectionFeatures) :
        self.sectionFeatures = sectionFeatures
        logging.debug(self.sectionFeatures)
        
    def setEntryPointFeatures(self, entryPointFeatures) :
        self.entryPointFeatures = entryPointFeatures
        logging.debug(self.entryPointFeatures)
        
    def setRelocationFeatures(self, relocationFeatures) :
        self.relocationFeatures = relocationFeatures
        logging.debug(self.relocationFeatures)

    def setStringFeatures(self, stringsFeatures) :
        self.stringsFeatures = stringsFeatures
        logging.debug(self.stringsFeatures)

    def setNamespaceFeatures(self, namespaceFeatures) :
        self.namespaceFeatures = namespaceFeatures
        logging.debug(self.namespaceFeatures)

    def setImportFeatures(self, importFeatures) :
        self.importFeatures = importFeatures
        logging.debug(self.importFeatures)

    def setSlackFeatures(self, slackFeatures) :
        self.slackFeatures = slackFeatures
        logging.debug(self.slackFeatures)

#--------------------------------------------------------------------------------------------
# Collater functions
#-------------------------------------------------------------------------------------------- 
    def getProcessFeatureTable(self) :

        processDetails = pd.DataFrame({'processName': [self.processName], 'processType': [self.processType]})

        processFeatures = pd.concat([processDetails, self.headerFeatures, self.registryFeatures, self.flagFeatures, 
                                    self.sectionFeatures, self.entryPointFeatures, self.relocationFeatures, 
                                    self.stringsFeatures, self.namespaceFeatures, self.importFeatures, self.slackFeatures], axis=1)        

        return processFeatures

