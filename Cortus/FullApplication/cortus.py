# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# The Cortus Application
#
# The purpose of this application is to provide a user the ability to train a model using only process memory dumps
# and then provide memory dump inputs of unknown processes that would enable them to determine if a process is benign
# or malicious.
# ------------------------------------------------------------------------------------------------------------------

import argparse
import csv
import datasetCreator
import logging
import model
import featureExtractor
import pandas as pd
import PySimpleGUI as sg
import numpy as np
import os
import sys

from tkinter.font import Font

maxInt = sys.maxsize
while True:
    # decrease the maxInt value by factor 10 
    # as long as the OverflowError occurs.
    try:
        csv.field_size_limit(maxInt)
        break
    except OverflowError:
        maxInt = int(maxInt/10)

logging.basicConfig(level=logging.INFO)
sg.theme('Black')

workingDirectory = os.path.dirname(os.path.abspath(__file__))
iconImg = os.path.join(workingDirectory, 'resources\CortusLogoTask.png')

class CortusApplication:
    model       = None
    extractor   = None
    dataset     = None


    def handleCmdLineCommands(self) :
        logging.warning("Commmand Line Use is Deprecated")
        parser = argparse.ArgumentParser(description="Cortus Analyser")
        parser.add_argument('--createModel', dest='createModel', type=bool, help='Run the application to train a model')
        parser.add_argument('--createModel', dest='createModel', type=bool, help='Run the application to train a model')
        parser.add_argument('--createModel', dest='createModel', type=bool, help='Run the application to train a model')


    def testProcessModel(self, modelFile, dmpFile) :
        modelManagementColumn  = [ [sg.Text("Cortus Data Collation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Train Model from Dataset', key="-TRAINMODEL-")],
                                  [sg.Text("Dataset: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-DATASET-"),
                                   sg.FilesBrowse('Select')], 
                                  [sg.Button('Test Model', key="-TESTMODELDETAILS-")],
                                  [sg.Text("Model File: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-MODEL-"),
                                   sg.FilesBrowse('Select')]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Dataset Creation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.VSeperator(),
                                   sg.Column(modelManagementColumn, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]

        modelWindow = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')
        while True:
            event, values = modelWindow.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                modelWindow.close()
                break
            if event == "-TRAINMODEL-" :
                dataset = values["-DATASET-"]
                model.CortusModel(dataset)
            if event == "-TESTMODELDETAILS-" :
                loadedModel = values["-MODEL-"]
                model.CortusModel(loadedModel)


    def createModel(self) :
        modelManagementColumn  = [ [sg.Text("Cortus Data Collation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Train Model from Dataset', key="-TRAINMODEL-")],
                                  [sg.Text("Dataset: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-DATASET-"),
                                   sg.FilesBrowse('Select')], 
                                  [sg.Button('Test Model', key="-TESTMODELDETAILS-")],
                                  [sg.Text("Model File: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-MODEL-"),
                                   sg.FilesBrowse('Select')]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Dataset Creation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.VSeperator(),
                                   sg.Column(modelManagementColumn, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]

        modelWindow = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')
        while True:
            event, values = modelWindow.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                modelWindow.close()
                break
            if event == "-TRAINMODEL-" :
                dataset = values["-DATASET-"]
                model.CortusModel(dataset)
            if event == "-TESTMODELDETAILS-" :
                loadedModel = values["-MODEL-"]
                model.CortusModel(loadedModel)


    def createCsvViewerWindow(self, filename) :
        try:
            data = []
            header_list = []
            df = pd.read_pickle(filename)
            data = df.values.tolist() 
            header_list = df.iloc[0].tolist()
            data = df[1:].values.tolist()

            tableLayout = [ [sg.Table(values=data,
                            headings=header_list,
                            auto_size_columns=True,
                            vertical_scroll_only = False,
                            key="fileTable", size=(1800, 300))],
                            [sg.Button('Exit')]
                           ]
            frameWindow = sg.Window(filename + ' Table', tableLayout, size = (1800, 400))
            while True:
                event, values = frameWindow.read()
                if event == "Exit" or event == sg.WIN_CLOSED:
                    break
        except Exception as e:
            logging.error(e)
            pass


    def createDataCSVSetWindow(self) :
        dataManagementColumn  = [ [sg.Text("Cortus Data Collation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('View selected Process Frame', key="-LOADPKLDATASET-")], 
                                  [sg.Button('View Stats', key="-VIEWSTATS-")],
                                  [sg.Button('Create Dataset', key='-CREATEDATASET-'),
                                   sg.In(size=(30, 2), enable_events=True, key="-OUTFOLDER-"),
                                   sg.FolderBrowse()]
                                ]
        ben_file_list_column  = [ [sg.Text("PKL Benign Folder"),
                                   sg.In(size=(30, 2), enable_events=True, key="-BENFOLDER-"),
                                   sg.FolderBrowse(),],
                                  [sg.Listbox(values=[], enable_events=True, size=(60, 20), key="-BENFILELIST-")]
                                ]
        mal_file_list_column  = [ [sg.Text("PKL Malicious Folder"),
                                   sg.In(size=(30, 2), enable_events=True, key="-MALFOLDER-"),
                                   sg.FolderBrowse(),],
                                  [sg.Listbox(values=[], enable_events=True, size=(60, 20), key="-MALFILELIST-")]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Dataset Creation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.VSeperator(),
                                   sg.Column(dataManagementColumn, vertical_alignment='t'),
                                   sg.VSeperator(),
                                   sg.Column(ben_file_list_column, vertical_alignment='t'),
                                   sg.VSeperator(),
                                   sg.Column(mal_file_list_column, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]

        csvWindow = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')
        while True:
            event, values = csvWindow.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                csvWindow.close()
                break

            if event == "-BENFOLDER-":
                folder = values["-BENFOLDER-"]
                try:
                    # Get list of files in folder
                    file_list = os.listdir(folder)
                except:
                    file_list = []
                fnames = [f for f in file_list if os.path.isfile(os.path.join(folder, f)) and f.lower().endswith((".pkl"))]
                csvWindow["-BENFILELIST-"].update(fnames)

            if event == "-MALFOLDER-":
                folder = values["-MALFOLDER-"]
                try:
                    # Get list of files in folder
                    file_list = os.listdir(folder)
                except:
                    file_list = []
                fnames = [f for f in file_list if os.path.isfile(os.path.join(folder, f)) and f.lower().endswith((".pkl"))]
                csvWindow["-MALFILELIST-"].update(fnames)
                
            if event == "-CREATEDATASET-" :
                benInfolder = values["-BENFOLDER-"]
                malInfolder = values['-MALFOLDER-']
                outFolder   = values['-OUTFOLDER-']
                datasetCreator.DataLoader(benInfolder, malInfolder, outFolder)
                

    def extractFeaturesFromDMPWindow(self) :
        dataManagementColumn  = [ [sg.Text("Cortus Data Extractor", font=("40"))],
                                  [sg.HorizontalSeparator()]
                                ]
        file_list_column      = [ [sg.Text("DMP Folder"),
                                   sg.In(size=(30, 2), enable_events=True, key="-DMPFOLDER-"),
                                   sg.FolderBrowse(),],
                                  [sg.Listbox(values=[], enable_events=True, size=(60, 20), key="-FILELIST-")],
                                  [sg.Button('Extract Features from DMP\'s', key="-EXTRACTFEATURES-"),
                                   sg.Text("Process Type:", key="-PROCESSTYPE-"),
                                   sg.Checkbox(text='Benign', key="-PROCESSTYPEBEN-"),
                                   sg.Checkbox(text='Malicious', key="-PROCESSTYPEMAL-")],
                                   [sg.In(size=(30, 2), enable_events=True, key="-OUTFOLDER-"),
                                   sg.FolderBrowse()],
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Dataset Creation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.VSeperator(),
                                   sg.Column(dataManagementColumn, vertical_alignment='t'),
                                   sg.VSeperator(),
                                   sg.Column(file_list_column, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]

        dmpWindow = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')
        while True:
            event, values = dmpWindow.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                dmpWindow.close()
                break
            if event == "-DMPFOLDER-":
                folder = values["-DMPFOLDER-"]
                try:
                    # Get list of files in folder
                    file_list = os.listdir(folder)
                except:
                    file_list = []
                fnames = [f for f in file_list if os.path.isfile(os.path.join(folder, f)) and f.lower().endswith((".dmp"))]
                dmpWindow["-FILELIST-"].update(fnames)
            if event == "-EXTRACTFEATURES-" :
                infolder    = values["-DMPFOLDER-"]
                outfolder   = values['-OUTFOLDER-']
                processType = values["-PROCESSTYPEBEN-"] if not None else values["-PROCESSTYPEMAL-"]
                featureExtractor.MemoryFeatureExtractor(infolder, outfolder, processType)


    def createStartupLayout(self) :
        modelManagementColumn = [ [sg.Text("Cortus Model Management")],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Create Model', key="-CREATEMODEL-")],
                                  [sg.Button('Load and View Model', key="-LOADMODEL-")], 
                                ]
        analysisColumn        = [ [sg.Text("Cortus Analysis and Detection Management")],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Analyse Process', key="-TESTPROCESS-")], 
                                  [sg.Button('Review Recent Analyses', key="-REVIEWANALYSIS-")]
                                ]
        dataManagementColumn  = [ [sg.Text("Cortus Data Management")],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Analyse Created Dataset', key="-VIEWSTATS-")],
                                  [sg.Button('Extract Features from DMP files', key="-LOADDMPPROCESSDATASET-")],
                                  [sg.Button('Create and Pre-process Pickle Dataset', key="-CREATECSVDATASET-")]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Cortus Data Management", font=("40"))],
                                  [sg.Image(os.path.join(workingDirectory, 'resources\CortusLogo.png'), size=(200, 200), key='-IMAGE-')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Column(modelManagementColumn, vertical_alignment='t'),
                                   sg.Column(analysisColumn, vertical_alignment='t'),
                                   sg.VSeperator(),
                                   sg.Column(dataManagementColumn, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]
        return layout


    def startApplication(self) :
        layout = self.createStartupLayout()
        window = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')

        while True:
            event, values = window.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                break
            if event == '-LOADMODEL-' :
                self.createModelManagementWindow()
            if event == '-CREATEMODEL-' :
                self.createModel()
            if event == '-CREATECSVDATASET-' :
                self.createDataCSVSetWindow()
            if event == '-LOADDMPPROCESSDATASET-' :
               self.extractFeaturesFromDMPWindow()
            if event == '-VIEWSTATS-' :
                self.createStatsWindow()
            if event == '-TESTPROCESS-' :
                self.createTestingWindow()
            if event == '-REVIEWANALYSIS-' :
                self.createAnalysisHistoryWindow()    
        window.close()
        exit()

    def __init__(self):
        self.startApplication()
        # self.handleCommands()


# if __name__ == '__main__':
CortusApplication()
