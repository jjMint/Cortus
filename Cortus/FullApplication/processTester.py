
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
    loading     = True

    def __init__(self, testModel, process):
        logging.info("Creating Cortus Malware Analysis Model")

        with open(testModel, 'rb') as modelFile:
            modelDetails = pickle.load(modelFile)
        self.model = modelDetails['Model']
        with open(os.path.join(workingDirectory, 'resources/Cortus_PCA.pkl'), 'rb') as pcaFile:
            self.pca = pickle.load(pcaFile)
        with open(os.path.join(workingDirectory, 'resources/Cortus_Scaler.pkl'), 'rb') as scalerFile:
            self.scaler = pickle.load(scalerFile)
        with open(os.path.join(workingDirectory, 'resources/Cortus_SetColumns.pkl'), 'rb') as columnFile:
            self.columnList = pickle.load(columnFile)

        processFile = featureExtractor.MemoryFeatureExtractor(inputFile=process, flag="Single").getTestProcess()
        processFile = datasetCreator.DataLoader(singleFrame=processFile, flag="Single").getTestProcess()
        processFile = processFile.drop(['processType'], 1)
        processFile = processFile[processFile.T[processFile.dtypes!=np.object].index]
        processFile = processFile.reindex(columns=self.columnList, fill_value=0)

        X_test = self.scaler.transform(processFile)
        X_test = self.pca.transform(X_test)
        predicted_label = self.model.predict(X_test)
        self.loading = False

        result = "Unknown"
        if predicted_label[0] == 0:
            result = "Benign"
        if predicted_label[0] == 1:
            result == "Malicious"

        accuracyConfidence = round(modelDetails['Accuracy'], 2)
        precisionConfidence = round(modelDetails['Average Precision'], 2)

        logging.info(result)
        self.createModelLayout(result, process, accuracyConfidence, precisionConfidence)


    def createModelLayout(self, result, process, accuracyConfidence, precisionConfidence) :
        sg.popup(f'Process {process} is determined to be {result} with confidence of {accuracyConfidence}')

    def loadingScreeen(self) :
        imageElement = sg.Image(os.path.join(workingDirectory, 'resources\loadingbar.gif'), size=(400, 400), key='-IMAGE-')
        layout = [  
                    [sg.Text('Testing Process....', font='ANY 15')],
                    [imageElement]
                ]
        modelWindow = sg.Window("Cortus Malware Analyzer ( Loading and Clustering Data ) ", layout, element_justification='c')

        while self.loading is True :
            event, values = modelWindow.read(timeout=100)
            modelWindow.Element('-IMAGE-').UpdateAnimation(os.path.join(workingDirectory, 'resources\loadingbar.gif'), 100)
        
        modelWindow.close()