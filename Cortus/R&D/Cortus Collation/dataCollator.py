# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory collation class that defines the process of extracting features using radare2
# ------------------------------------------------------------------------------------------------------------------

import argparse
import logging
import os
import pandas as pd
import sys

from tqdm import tqdm

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


def cleanProcessFeatures(processFeatureFrame) :
    processFeatureFrame = processFeatureFrame.dropna(axis=1)
    processFeatureFrame = processFeatureFrame.fillna(0)
    processFeatureFrame = processFeatureFrame.drop(['baddr', 'bintype', 'file', 'humansz'], axis=1)
    return processFeatureFrame


# --------------------------------------------------------------------------------------------
# // DataLoader
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with collation processes to create full dataset
# --------------------------------------------------------------------------------------------
class DataLoader :
    inputFolder       = None
    outputFolder      = None
    combinedDataFrame = None

    def __init__(self, inputFolder, outputFolder) :
        self.inputFolder = inputFolder
        self.outputFolder = outputFolder

    def saveData(self, dataSet, count) :
        dataSet.to_csv(os.path.join(os.fsdecode(self.outputFolder), 'datasetFinal{}.csv'.format(count)))

    def loadData(self) :
        processFeatureFrames = []
        largerFrames = []
        counter = 0

        for csvFile in tqdm(os.listdir(self.inputFolder)) :
            csvFileName = os.fsdecode(csvFile)
            csvFilePath = os.path.join(os.fsdecode(self.inputFolder), csvFileName)

            processFeatures = pd.read_csv(csvFilePath)
            processFeatures = cleanProcessFeatures(processFeatures)
            processFeatureFrames.append(processFeatures)

        finalDataset = pd.concat(processFeatureFrames, ignore_index=True, axis='rows')
        logging.debug(finalDataset)
        self.saveData(finalDataset, 'final')
        
def main(argv) :
    parser = argparse.ArgumentParser(description='Create a complete dataset based on input files')
    parser.add_argument('--iFolder', dest='inputFolder', help='The input folder for process csvs')
    parser.add_argument('--oFolder', dest='outputFolder', help='The ouput folder for process csv')

    args = parser.parse_args()

    dataLoader = DataLoader(args.inputFolder, args.outputFolder)
    dataLoader.loadData()

if __name__ == "__main__":
    main(sys.argv[1:])
