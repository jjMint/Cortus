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
import datasetAnalyser
import logging
import model
import featureExtractor
import pandas as pd
import processTester
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


    def testProcessModel(self) :
        modelManagementColumn  = [ [sg.Text("Cortus Malware Analyzer Testing", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Text("Model: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-MODEL-"),
                                   sg.FilesBrowse('Select')],
                                  [sg.Text("Process to be tested", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-PROCESS-"),
                                   sg.FilesBrowse('Select')],
                                  [sg.Button('Begin Test', key="-TESTPROCESS-")],
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Test Model With Process", font=("40"))],
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
            if event == "-TESTPROCESS-" :
                modelFile = values["-MODEL-"]
                processFile = values["-PROCESS-"]
                processTester.CortusModelTester(modelFile, processFile)


    def createModel(self) :
        modelManagementColumn  = [ [sg.Text("Cortus Malware Analyzer", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Train Model from Collated Dataset', key="-TRAINMODEL-")],
                                  [sg.Text("Dataset: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-DATASET-"),
                                   sg.FilesBrowse('Select')]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Model Creation", font=("40"))],
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
                model.CortusModelCreator(dataset)


    def createPklViewerWindow(self, filename) :
        try:
            data = []
            header_list = []
            df = pd.read_pickle(filename)
            data = df.values.tolist() 
            header_list = df.columns.tolist()

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


    def createDataPKLSetWindow(self) :
        dataManagementColumn  = [ [sg.Text("Cortus Data Collation", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Text('Selected a Process to open a viewing frame', key="-LOADPKLDATASET-")], 
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
            if event == "-BENFILELIST-":
                filename = os.path.join(values["-BENFOLDER-"], values["-BENFILELIST-"][0])
                self.createPklViewerWindow(filename)
            if event == "-MALFILELIST-":
                filename = os.path.join(values["-MALFOLDER-"], values["-MALFILELIST-"][0])
                self.createPklViewerWindow(filename)
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


    def createStatsWindow(self) :
        statsManagementColumn  = [ [sg.Text("Cortus Malware Analyzer", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Analyze Collated Dataset', key="-ANALYZE-")],
                                  [sg.Text("Dataset: ", font=("15")),
                                   sg.In(size=(30, 2), enable_events=True, key="-DATASET-"),
                                   sg.FilesBrowse('Select')]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Dataset Analyzer", font=("40"))],
                                  [sg.HorizontalSeparator()],
                                  [sg.VSeperator(),
                                   sg.Column(statsManagementColumn, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]

        statsWindow = sg.Window("Cortus Malware Analyzer", layout, element_justification='c')
        while True:
            event, values = statsWindow.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                statsWindow.close()
                break
            if event == "-ANALYZE-":
                dataset = values["-DATASET-"]
                datasetAnalyser.DatasetAnalyser(dataset)


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
                    file_list = os.listdir(folder)
                except:
                    file_list = []
                fnames = [f for f in file_list if os.path.isfile(os.path.join(folder, f)) and f.lower().endswith((".dmp"))]
                dmpWindow["-FILELIST-"].update(fnames)
            if event == "-EXTRACTFEATURES-" :
                infolder    = values["-DMPFOLDER-"]
                outfolder   = values['-OUTFOLDER-']
                if values["-PROCESSTYPEBEN-"] == 1 :
                    processType = "Benign"
                elif values["-PROCESSTYPEMAL-"] == 1 :
                    processType = "Malware"
                featureExtractor.MemoryFeatureExtractor(infolder, outfolder, processType)


    def createStartupLayout(self) :
        modelManagementColumn = [ [sg.Text("Cortus Model Management")],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Create Model', key="-CREATEMODEL-")],
                                  [sg.Button('Load and Test Model', key="-LOADMODEL-")],
                                ]
        dataManagementColumn  = [ [sg.Text("Cortus Data Management")],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Extract Features from DMP files', key="-LOADDMPPROCESSDATASET-")],
                                  [sg.Button('Create and Pre-process Pickle Dataset', key="-CREATEPKLDATASET-")],
                                  [sg.Button('Analyse Created Dataset Feature Importance and Correlation', key="-VIEWSTATS-")]
                                ]
        layout                = [ [sg.Titlebar("Cortus Malware Analyzer", icon=iconImg)],
                                  [sg.Text("Cortus Malware Analyzer", font=("50"))],
                                  [sg.Image(os.path.join(workingDirectory, 'resources\CortusLogo.png'), size=(200, 200), key='-IMAGE-')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Column(modelManagementColumn, vertical_alignment='t'),
                                   sg.VSeperator(),
                                   sg.Column(dataManagementColumn, vertical_alignment='t')],
                                  [sg.HorizontalSeparator()],
                                  [sg.Button('Exit')]
                                ]
        return layout


    def startApplication(self) :
        layout = self.createStartupLayout()
        window = sg.Window("Cortus Malware Analyzer", layout, element_justification='c', element_padding=10)

        while True:
            event, values = window.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                break
            if event == '-LOADMODEL-' :
                self.testProcessModel()
            if event == '-VIEWMODEL-' :
                self.viewModel()
            if event == '-CREATEMODEL-' :
                self.createModel()
            if event == '-CREATEPKLDATASET-' :
                self.createDataPKLSetWindow()
            if event == '-LOADDMPPROCESSDATASET-' :
               self.extractFeaturesFromDMPWindow()
            if event == '-VIEWSTATS-' :
                self.createStatsWindow()  
        window.close()
        exit()


    def __init__(self):
        self.startApplication()


CortusApplication()
