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

    def __init__(self, processName, processType):
        self.processName = processName
        self.processType = processType

#--------------------------------------------------------------------------------------------
# Process Setters
#--------------------------------------------------------------------------------------------
    def setHeaderFeatures(self, headerFeatures) :
        self.headerFeatures = headerFeatures
        # pprint.pprint(self.headerFeatures)
        
    def setRegistryFeatures(self, registryFeatures) :
        self.registryFeatures = registryFeatures
        # pprint.pprint(self.registryFeatures)

    def setFlagFeatures(self, flagFeatures) :
        self.flagFeatures = flagFeatures
        # pprint.pprint(self.flagFeatures)

    def setSectionFeatures(self, sectionFeatures) :
        self.sectionFeatures = sectionFeatures
        # pprint.pprint(self.sectionFeatures)
        
    def setEntryPointFeatures(self, entryPointFeatures) :
        self.entryPointFeatures = entryPointFeatures
        # pprint.pprint(self.entryPointFeatures)
        
    def setRelocationFeatures(self, relocationFeatures) :
        self.relocationFeatures = relocationFeatures
        # pprint.pprint(self.relocationFeatures)

    def setStringFeatures(self, stringsFeatures) :
        self.stringsFeatures = stringsFeatures
        # pprint.pprint(self.stringsFeatures)

    def setNamespaceFeatures(self, namespaceFeatures) :
        self.namespaceFeatures = namespaceFeatures
        # pprint.pprint(self.namespaceFeatures)

    def setImportFeatures(self, importFeatures) :
        self.importFeatures = importFeatures
        # pprint.pprint(self.importFeatures)

#--------------------------------------------------------------------------------------------
# Collater functions
#-------------------------------------------------------------------------------------------- 
    def getProcessFeatureTable(self) :

        processDetails = pd.DataFrame({'processName': [self.processName], 'processType': [self.processType]})

        print(processDetails)

        processFeatures = pd.concat([processDetails, self.headerFeatures, self.registryFeatures, self.flagFeatures, 
                                    self.sectionFeatures, self.entryPointFeatures, self.relocationFeatures, 
                                    self.stringsFeatures, self.namespaceFeatures, self.importFeatures], axis=1)        

        return processFeatures

