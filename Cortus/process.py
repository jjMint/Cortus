# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import pandas as pd
import pprint

# --------------------------------------------------------------------------------------------
# // Process Object
# --------------------------------------------------------------------------------------------
# Class that handles the collation and storage of a dump / processes features
class Process :
    processName         = None
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
