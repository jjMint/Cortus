import numpy as np
import os
import sys
import logging
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LinearRegression

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))

class DatasetAnalyser :
    dataset       = None
    datasetLabels = None

    def __init__(self, dataset, flag=None) :
        self.dataset = pd.read_pickle(dataset)
        self.datasetLabels = self.dataset['processType']

        dataset = self.dataset.drop(['processType'], 1)
        dataset = dataset[dataset.T[dataset.dtypes!=np.object].index]

        self.analyzeProcessedDatasetImportance(dataset)

    def analyzeProcessedDatasetImportance(self, dataset) :

        label_encoder     = LabelEncoder()
        true_labels       = label_encoder.fit_transform(self.datasetLabels)
        scaler = StandardScaler()
        stdData = scaler.fit_transform(dataset)

        model = RandomForestClassifier()
        model.fit(stdData, true_labels)
        importance = model.feature_importances_
        for i,v in enumerate(importance):
            feature = self.dataset.columns[i]
            print('Feature: %s, Score: %.5f' % (feature,v))

        fig, (ax1) = plt.subplots(nrows=1, ncols=1, figsize=(20,10))
        fig.suptitle('Dataset Results and Analysis', fontsize=16)
        plt.bar([x for x in range(len(importance))], importance)
        plt.show()






