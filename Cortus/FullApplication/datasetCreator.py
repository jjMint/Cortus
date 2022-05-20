# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory collation class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import logging
import math
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
np.random.seed(0)

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


    def __init__(self, benInputFolder=None, malInputFolder=None, outputFolder=None, flag=None, singleFrame=None) :
        logging.info("Beginning Data Collation")
        self.benInputFolder = benInputFolder
        self.malInputFolder = malInputFolder
        self.outputFolder = outputFolder

        if flag == "Single" :
            self.loadSingleData(singleFrame)
        else :
            self.loadData()


    def _saveData(self, dataset, count) :
        dataset.to_pickle(os.path.join(os.fsdecode(self.outputFolder), 'dataset{}.pkl'.format(count)))


    def processAndSaveData(self, processFrame) :
        dataset = pd.concat(processFrame)
        dataset = dataset.reset_index(drop=True)

        dataset = self.dataPreProcessing(dataset)
        dataset = self.minhashPreProcessing(dataset)
        logging.info(dataset)
        self._saveData(dataset, 'final')
        self.combinedDataFrame = dataset

        return dataset


    def loadSingleData(self, singleFrame) :
        processFeatures = cleanProcessFeatures(singleFrame)
        processFeatures = self.dataPreProcessing(processFeatures)
        processFeatures = self.minhashPreProcessing(processFeatures)

        return processFeatures


    def loadData(self) :
        processFeatureFrames = []
        count = 0

        for file in tqdm(os.listdir(self.benInputFolder)) :
            numFiles = len(os.listdir(self.benInputFolder))
            sg.one_line_progress_meter('Benign Set Collation', count + 1, numFiles)
            fileName = os.fsdecode(file)
            filePath = os.path.join(os.fsdecode(self.benInputFolder), fileName)

            processFeatures = pd.read_pickle(filePath)
            processFeatures = cleanProcessFeatures(processFeatures)
            processFeatureFrames.append(processFeatures)
            count = count + 1
        count = 0

        for file in tqdm(os.listdir(self.malInputFolder)) :
            numFiles = len(os.listdir(self.malInputFolder))
            sg.one_line_progress_meter('Malware Set Collation', count + 1, numFiles)
            fileName = os.fsdecode(file)
            filePath = os.path.join(os.fsdecode(self.malInputFolder), fileName)

            processFeatures = pd.read_pickle(filePath)
            processFeatures = cleanProcessFeatures(processFeatures)
            processFeatureFrames.append(processFeatures)
            count = count + 1

        # This step can take a while so provide a loading screen for the user
        t1 = threading.Thread(target=self.processAndSaveData, args=(processFeatureFrames,))
        t1.start()
        self.loadingScreeen()
        t1.join()


    def dataPreProcessing(self, dataset) :
        # Drop na values where all are present, along with filling na values with 0 for oddities.
        logging.info("Processing Dataset")
        dataset = dataset.dropna(axis=1, how='all')
        dataset = dataset.fillna(0)

        # Find counts of level of permissions
        dataset[dataset.filter(regex='_perms').columns] = dataset[dataset.filter(regex='_perms').columns].apply(lambda col:(pd.Categorical(col).codes))
        dataset = pd.concat([dataset, pd.DataFrame(dataset[dataset.filter(regex='_perms').columns].stack().groupby(level=0).value_counts().unstack(fill_value=0).add_prefix("permissionTypeCount_"))], axis=1)
        dataset = dataset.drop(dataset.filter(regex='_perms').columns, axis=1)

        # Grab count of interesting memory sections per process dump
        dataset = dataset.drop(dataset.filter(regex='Memory_Section').columns, axis=1)
        dataUniqueMemorySectionCount = dataset[dataset.filter(regex='_size').columns].gt(0).sum(axis=1)
        dataset['uniqueMemorySectionCount'] = dataUniqueMemorySectionCount
        dataset = dataset.drop(dataset.filter(regex='_size').columns, axis=1)

        # Clean up string data into categorical data
        dataset['arch']     = pd.Categorical(dataset['arch']).codes
        dataset['bits']     = pd.Categorical(dataset['bits']).codes
        dataset['canary']   = pd.Categorical(dataset['canary']).codes
        dataset['retguard'] = pd.Categorical(dataset['retguard']).codes
        dataset['crypto']   = pd.Categorical(dataset['crypto']).codes
        dataset['endian']   = pd.Categorical(dataset['endian']).codes
        dataset['flags']    = pd.Categorical(dataset['flags']).codes
        dataset['havecode'] = pd.Categorical(dataset['havecode']).codes
        dataset['machine']  = pd.Categorical(dataset['machine']).codes
        dataset['static']   = pd.Categorical(dataset['static']).codes

        # Drop unnecessary columns either due to null strings, statistical outliers or lack of contextual info following analysis
        dataset = dataset.drop(['class', 'minopsz', 'va', 'fd', 'maxopsz', 'invopsz', 
                                'block', 'compiled', 'compiler', 'dbg_file', 'hdr.csum', 'guid', 
                                'intrp', 'lang', 'cc', 'rip', 'pc', 'machine', 'bits', 'binsz'], 1)

        # Drop process name and all '0' only columns
        dataset = dataset.iloc[: , 1:]
        dataset = dataset.loc[:, ~dataset.eq(0).all()]

        return dataset


    def minhashPreProcessing(self, dataset) :
        # Make a list of the relevant columns we want to MinHash 
        hashColumnLists = [ ('stringContentFull', 'stringHash'), ('sectionContentFull', 'sectionHash'), ('sectionSizeFull', 'sectionSizeHash'), 
                            ('sectionPermsFull', 'sectionPermsHash'), ('relocationContentFull', 'relocationHash'), ('importNameContentFull', 'importNameHash'), ('importLibContentFull', 'importLibHash')]

        buckets = 600/450 # here we define the end number of buckets as ~1 which results in bucket value that can be used as a cluster
        plane  = math.ceil(np.log2(buckets))
        planes = np.array([np.random.normal(size=(128, plane)) for _ in range(10)])

        # For each, create a hash, and add the relevant hash columns to the current dataset
        for seriesColumn in hashColumnLists :
            logging.info(f"Hashing {seriesColumn[0]}")
            hashBucketFrame = self.stringToMinhash(dataset[seriesColumn[0]], f"{seriesColumn[1]}", 128, planes)
            dataset = pd.concat([dataset, hashBucketFrame], axis=1)

        # Drop the full content and any other columns that don't contain points of interest
        dataset = dataset.drop(['sectionContentFull', 'sectionSizeFull', 'sectionPermsFull', 'stringContentFull', 'relocationContentFull', 'importNameContentFull', 'importLibContentFull'], 1)
        datasetlabels = dataset[['processType']]
        dataset = dataset[dataset.T[dataset.dtypes!=np.object].index]
        dataset['processType'] = datasetlabels

        return dataset


    def stringToMinhash(self, stringSeries, hashingPrefix, hashLength, planes) :
        minhashList = []

        m = MinHash(num_perm=hashLength)
        for row in stringSeries :
            for s in row :
                m.update(s.encode('utf8'))
            minhashList.append(m.digest().tolist())
           
        clusterBucketList = []
        for i in range(len(minhashList)):
            minhashList[i] = minhashList[i]
            clusterBucketList.append(self.bucket_value_of_vector(minhashList[i], planes))
        logging.info("Created Hash Cluster")
        hashFrame = pd.DataFrame(clusterBucketList)
        hashFrame.columns = [hashingPrefix]

        return hashFrame

    
    def bucket_value_of_vector(self, v, planes):
        dot_product = np.dot(v, planes)
        sign_of_dot_product = np.sign(dot_product)

        h = sign_of_dot_product >= 0
        h = np.squeeze(h)

        hash_value = 0
        n_planes = planes.shape[0]
        for i in range(n_planes):
            hash_value += 2**i * h[i]

        hash_value = hash_value.astype(int)

        return hash_value

    
    def loadingScreeen(self) :
        imageElement = sg.Image(os.path.join(workingDirectory, 'resources\loadingbar.gif'), size=(400, 400), key='-IMAGE-')
        layout = [  
                    [sg.Text('Loading....', font='ANY 15')],
                    [imageElement]
                ]
        modelWindow = sg.Window("Cortus Malware Analyzer ( Loading and Clustering Data ) ", layout, element_justification='c')

        while self.combinedDataFrame is None :
            event, values = modelWindow.read(timeout=100)
            modelWindow.Element('-IMAGE-').UpdateAnimation(os.path.join(workingDirectory, 'resources\loadingbar.gif'), 100)
        
        modelWindow.close()
