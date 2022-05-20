import numpy as np
import os
import sys
import logging
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import PySimpleGUI as sg

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))
sns.set_theme(style="white")

class DatasetAnalyser :
    dataset       = None
    datasetLabels = None

    def __init__(self, dataset, flag=None) :
        self.dataset = pd.read_pickle(dataset)
        self.datasetLabels = self.dataset['processType']

        dataset = self.dataset.drop(['processType'], 1)
        dataset = dataset[dataset.T[dataset.dtypes!=np.object].index]
        logging.info(dataset)

        self.analyseProcessedDatasetImportance(dataset)


    def analyseProcessedDatasetImportance(self, dataset) :
        label_encoder     = LabelEncoder()
        true_labels       = label_encoder.fit_transform(self.datasetLabels)
        scaler = StandardScaler()
        stdData = scaler.fit_transform(dataset)

        model = RandomForestClassifier()
        model.fit(stdData, true_labels)
        importance = model.feature_importances_
        importanceFrame = {}
        for i,v in enumerate(importance):
            feature = dataset.columns[i]
            importanceFrame[feature] = v

        importanceFrame = pd.DataFrame.from_dict(importanceFrame, orient='index')
        importanceFrame.columns =['Feature Importance']
        logging.info(importanceFrame)

        fig, (ax1) = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
        fig.suptitle('Dataset Feature Importance', fontsize=16)
        importanceFrame.plot.bar(stacked=True, ax=ax1)
        fig.show()

        fig2, (ax2) = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
        fig2.suptitle('Dataset Feature Correlation', fontsize=16)
        corrDataset = self.dataset
        corrDataset['processType'] = pd.Categorical(corrDataset['processType']).codes
        corrDataset = corrDataset.corr().round(2)
        sns.heatmap(corrDataset, ax=ax2)
        fig2.show()

