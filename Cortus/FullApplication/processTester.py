
import matplotlib.pyplot as plt
import numpy as np
import logging
import os
import pandas as pd
import featureExtractor
import datasetCreator
import pickle
import PySimpleGUI as sg
import sys
import seaborn as sns


np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))
iconImg = os.path.join(workingDirectory, 'resources\CortusLogoTask.png')

class CortusModelTester:
    # Define the model, dataset and outpath for saving
    #-- Options and Built Models --
    model             = None
    processFile       = None

    def __init__(self, testModel, process):
        logging.info("Creating Cortus Malware Analysis Model")

        with open(testModel, 'rb') as modelFile:
            self.model = pickle.load(modelFile)

        self.processFile = featureExtractor.MemoryFeatureExtractor(inputFile=process, flag="Single")
        self.processFile = datasetCreator.DataLoader(self.processFile, flag="Single")

        self.processFile = self.processFile.drop(['processType'], 1)
        self.processFile = self.processFile[self.processFile.T[self.processFile.dtypes!=np.object].index]

        predicted_labels = self.model.predict(self.processFile)
        logging.info(predicted_labels)

        # self.createModelLayout()


    def createModelLayout(self) :
        # sg.set_options(text_justification='right')       

        layout = [
                  [sg.Text('Mode Tester', font=('Helvetica', 16))],
                  [sg.HorizontalSeparator()],      
                  [sg.Text('Model Type', size=(15, 1))],      
                  [sg.HorizontalSeparator()],
                  [sg.Submit('CreateModel'), sg.Button('Exit')]
                 ]    

        window = sg.Window('Cortus Machine Learning Model', layout, font=("Helvetica", 12)) 

        # State operators for tabs
        opened1, opened2, opened3 = False, False, False

        while True:
            event, values = window.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                window.close()
                break
            if event.startswith('-OPEN SEC1-') or event.startswith('-SVM-'):
                opened1 = not opened1
                window['-OPEN SEC1-'].update(self.SYMBOL_DOWN if opened1 else self.SYMBOL_UP)
                window['-SEC1-'].update(visible=opened1)

                self.createModel(modelParams)