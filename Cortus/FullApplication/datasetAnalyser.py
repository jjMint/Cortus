import numpy as np
import os
import sys
import logging
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from sklearn.preprocessing import LabelEncoder, StandardScaler
# from sklearn.feature_selection import SelectKBest, chi2
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

        self.dataset = self.dataset.drop(['processType', 'registers'], 1)
        self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]

        self.analyzeProcessedDataset()


    def analyzeProcessedDataset(self) :

        label_encoder     = LabelEncoder()
        true_labels       = label_encoder.fit_transform(self.datasetLabels)
        scaler = StandardScaler()
        stdData = scaler.fit_transform(self.dataset)

        model = RandomForestClassifier()
        model.fit(stdData, true_labels)
        importance = model.feature_importances_
        for i,v in enumerate(importance):
            feature = self.dataset.columns[i]
            print('Feature: %s, Score: %.5f' % (feature,v))

        fig, (ax1) = plt.subplots(nrows=1, ncols=2, figsize=(20,10))
        fig.suptitle('Dataset Results and Analysis', fontsize=16)
        plt.bar([x for x in range(len(importance))], importance)
        plt.show()




