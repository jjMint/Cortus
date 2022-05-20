
from pyexpat import model
import numpy as np
import logging
import os
import featureExtractor
import datasetCreator
import pickle
import PySimpleGUI as sg
import sys

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))
iconImg = os.path.join(workingDirectory, 'resources\CortusLogoTask.png')


class CortusModelTester:
    # Define the model, dataset and outpath for saving
    #-- Options and Built Models --
    model       = None
    columnList  = None
    pca         = None
    scaler      = None

    def __init__(self, testModel, process):
        logging.info("Creating Cortus Malware Analysis Model")

        with open(testModel, 'rb') as modelFile:
            self.model = pickle.load(modelFile)
        with open(os.path.join(workingDirectory, 'resources/Cortus_PCA.pkl'), 'rb') as pcaFile:
            self.pca = pickle.load(pcaFile)
        with open(os.path.join(workingDirectory, 'resources/Cortus_Scaler.pkl'), 'rb') as scalerFile:
            self.scaler = pickle.load(scalerFile)
        with open(os.path.join(workingDirectory, 'resources/Cortus_SetColumns.pkl'), 'rb') as columnFile:
            self.columnList = pickle.load(columnFile)

        print(self.model)

        processFile = featureExtractor.MemoryFeatureExtractor(inputFile=process, flag="Single").getTestProcess()
        processFile = datasetCreator.DataLoader(singleFrame=processFile, flag="Single").getTestProcess()
        processFile = processFile.drop(['processType'], 1)
        processFile = processFile[processFile.T[processFile.dtypes!=np.object].index]
        processFile = processFile.reindex(columns=self.columnList, fill_value=0)

        X_test = self.scaler.transform(self.processFile)
        X_test = self.pca.transform(X_test)
        predicted_label = self.model.predict(X_test)

        result = "Unknown"
        if predicted_label[0] == 0:
            result = "Benign"
        if predicted_label[0] == 1:
            result == "Malicious"

        logging.info(result)
        self.createModelLayout(result, process)


    def createModelLayout(self, result, process) :
        sg.popup(f'Process {process} is determined to be {result} with a confidence of {result}')