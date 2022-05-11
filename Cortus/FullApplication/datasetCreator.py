# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory collation class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import logging
import numpy as np
import os
import PySimpleGUI as sg
import pandas as pd
import sys
import threading

from datasketch import MinHash
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))

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


def cleanProcessFeatures(processFeatureFrame) :
    processFeatureFrame = processFeatureFrame.dropna(how='all', axis=1)
    processFeatureFrame = processFeatureFrame.fillna(0)
    processFeatureFrame = processFeatureFrame.drop(['baddr', 'bintype', 'file', 'humansz'], axis=1)
    processFeatureFrame = processFeatureFrame.loc[:,~processFeatureFrame.columns.duplicated()]
    return processFeatureFrame


# --------------------------------------------------------------------------------------------
# // DataLoader
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with collation processes to create full dataset
# --------------------------------------------------------------------------------------------
class DataLoader :
    benInputFolder    = None
    malInputFolder    = None
    outputFolder      = None
    combinedDataFrame = None

    def __init__(self, benInputFolder, malInputFolder, outputFolder) :
        logging.info("Beginning Data Collation")

        self.benInputFolder = benInputFolder
        self.malInputFolder = malInputFolder
        self.outputFolder = outputFolder
        self.loadData()

    def saveData(self, dataset, count) :
        dataset.to_pickle(os.path.join(os.fsdecode(self.outputFolder), 'dataset{}.pkl'.format(count)))

    def loadData(self) :
        processFeatureFrames = []
        count = 0

        for csvFile in tqdm(os.listdir(self.benInputFolder)) :
            numFiles = len(os.listdir(self.benInputFolder))
            sg.one_line_progress_meter('Benign Set Collation', count + 1, numFiles)
            csvFileName = os.fsdecode(csvFile)
            csvFilePath = os.path.join(os.fsdecode(self.benInputFolder), csvFileName)

            processFeatures = pd.read_pickle(csvFilePath)
            processFeatures = cleanProcessFeatures(processFeatures)
            processFeatureFrames.append(processFeatures)
            count = count + 1
        count = 0

        for csvFile in tqdm(os.listdir(self.malInputFolder)) :
            numFiles = len(os.listdir(self.malInputFolder))
            sg.one_line_progress_meter('Malware Set Collation', count + 1, numFiles)
            csvFileName = os.fsdecode(csvFile)
            csvFilePath = os.path.join(os.fsdecode(self.malInputFolder), csvFileName)

            processFeatures = pd.read_pickle(csvFilePath)
            processFeatures = cleanProcessFeatures(processFeatures)
            processFeatureFrames.append(processFeatures)
            count = count + 1

        # This step can take a while so provide a loading screen for the user
        t1 = threading.Thread(target=self.processAndSaveData, args=(processFeatureFrames,))
        t1.start()
        # self.loadingScreeen()
        t1.join()


    # def loadingScreeen(self) :

    #     imageElement = sg.Image(os.path.join(workingDirectory, 'resources\loadingbar.gif'), size=(400, 400), key='-IMAGE-')
    #     layout = [  
    #                 [sg.Text('Loading....', font='ANY 15')],
    #                 [imageElement]
    #             ]
    #     modelWindow = sg.Window("Cortus Malware Analyzer ( Loading ) ", layout, element_justification='c')

    #     while self.combinedDataFrame is None :
    #         event, values = modelWindow.read(timeout=100)
    #         modelWindow.Element('-IMAGE-').UpdateAnimation(os.path.join(workingDirectory, 'resources\loadingbar.gif'), 100)
        
    #     modelWindow.close()

    def processAndSaveData(self, processFrame) :
        dataset = pd.concat(processFrame)
        dataset = dataset.reset_index(drop=True)

        dataset = self.dataPreProcessing(dataset)
        dataset = self.lshPreProcessing(dataset)
        logging.info(dataset)
        self.saveData(dataset, 'final')
        self.combinedDataFrame = dataset

        return dataset


    def dataPreProcessing(self, dataset) :
        # Find counts of level of permissions
        logging.info("Processing Dataset")
        dataset = dataset.dropna(axis=1, how='all')
        dataset = dataset.fillna(0)
        dataset[dataset.filter(regex='_perms').columns] = dataset[dataset.filter(regex='_perms').columns].apply(lambda col:(pd.Categorical(col).codes))
        dataset = pd.concat([dataset, pd.DataFrame(dataset[dataset.filter(regex='_perms').columns].stack().groupby(level=0).value_counts().unstack(fill_value=0).add_prefix("permissionCount_"))], axis=1)
        dataset = dataset.drop(dataset.filter(regex='_perms').columns, axis=1)

        # Grab count of interesting memory sections per process dump
        dataset = dataset.drop(dataset.filter(regex='Memory_Section').columns, axis=1)
        dataUniqueMemorySectionCount = dataset[dataset.filter(regex='_size').columns].gt(0).sum(axis=1)
        dataset['uniqueMemorySectionCount'] = dataUniqueMemorySectionCount
        dataset = dataset.drop(dataset.filter(regex='_size').columns, axis=1)

        # Clean up string data into categorical data
        dataset['arch'] = pd.Categorical(dataset['arch']).codes
        dataset['bits'] = pd.Categorical(dataset['bits']).codes
        dataset['canary'] = pd.Categorical(dataset['canary']).codes
        dataset['retguard'] = pd.Categorical(dataset['retguard']).codes
        dataset['crypto'] = pd.Categorical(dataset['crypto']).codes
        dataset['endian'] = pd.Categorical(dataset['endian']).codes
        dataset['flags'] = pd.Categorical(dataset['flags']).codes
        dataset['havecode'] = pd.Categorical(dataset['havecode']).codes
        dataset['machine'] = pd.Categorical(dataset['machine']).codes
        dataset['static'] = pd.Categorical(dataset['static']).codes

        dataset = dataset.iloc[: , 1:]
        dataset.loc[:, ~dataset.eq(0).all()]

        return dataset

    def lshPreProcessing(self, dataset) :
        hashColumnLists = [ ('stringContentFull', 'stringHash'), ('sectionContentFull', 'sectionHash'), ('sectionSizeFull', 'sectionSizeHash'), 
                            ('sectionPermsFull', 'sectionPermsHash'), ('relocationContentFull', 'relocationHash'), ('importNameContentFull', 'importNameHash'), ('importLibContentFull', 'importLibHash')]

        for seriesColumn in hashColumnLists :
            hashBucketFrame = self.stringToMinhash(dataset[seriesColumn[0]], f"{seriesColumn[1]}_", 1)
            dataset = pd.concat([dataset, hashBucketFrame], axis=1)

        dataset = dataset.drop(['sectionContentFull', 'sectionSizeFull', 'sectionPermsFull', 'stringContentFull', 'relocationContentFull', 'importNameContentFull', 'importLibContentFull'], 1)

        return dataset

    def stringToMinhash(self, stringSeries, hashingPrefix, hashLength) :
        minhashList = []
        m = MinHash(num_perm=hashLength)
        for row in stringSeries :
            for s in row :
                m.update(s.encode('utf8'))
            minhashList.append(m.digest().tolist())
        return pd.DataFrame(minhashList).add_prefix(hashingPrefix)
