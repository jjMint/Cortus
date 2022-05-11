# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# The Cortus Model
#
# The purpose of this file is to contain all functions and methods associated with the development
# training and storage of the trained Cortus model
# ------------------------------------------------------------------------------------------------------------------

import matplotlib.pyplot as plt
import numpy as np
import logging
import os
import pandas as pd
import sys
import seaborn as sns

from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler, MaxAbsScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn import svm
from datasketch import MinHash
from sklearn.neighbors import KNeighborsClassifier
from mlxtend.plotting import plot_decision_regions
from sklearn.feature_selection import SelectKBest, f_regression

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))

class CortusModel:
    # Define the model, dataset and outpath for saving
    model           = None
    dataset         = None
    outFolder       = None
    dataset_true_labels = None

    def __init__(self, dataset, outFolder, flag=None):
        logging.info("Creating Cortus Malware Analysis Model")
        self.dataset = pd.read_pickle(dataset)
        self.dataset = self.dataset.reset_index(drop=True)
        self.outFolder = outFolder

        # self.analyzeDataset(dataset)
        self.createModel(dataset)


    def analyzeDataset(self, dataset) :
        self.dataset = self.dataset.drop(['processType'], 1)
        self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]
        # self.dataset = self.dataset.astype('float')

        feature_selector = SelectKBest(f_regression, k = "all")
        fit = feature_selector.fit(self.dataset, true_labels)

        p_values = pd.DataFrame(fit.pvalues_)
        scores = pd.DataFrame(fit.scores_)
        input_variable_names = pd.DataFrame(self.dataset.columns)
        summary_stats = pd.concat([input_variable_names, p_values, scores], axis = 1)
        # summary_stats.to_csv(os.path.join(os.fsdecode(self.outFolder), 'datasetsummary.csv'))
        summary_stats.columns = ["input_variable", "p_value", "f_score"]
        summary_stats.sort_values(by = "p_value", inplace = True)

        p_value_threshold = 0.05
        score_threshold = 5

        selected_variables = summary_stats.loc[(summary_stats["f_score"] >= score_threshold) &
                                            (summary_stats["p_value"] <= p_value_threshold)]
        selected_variables = selected_variables["input_variable"].tolist()



        summary_stats.to_csv(os.path.join(os.fsdecode(self.outFolder), 'datasetsummary.csv'))

    def createModel(self, dataset):
        logging.info("Training and Testing Model")

        self.dataset_true_labels = self.dataset[['processType']]
        label_encoder   = LabelEncoder()
        true_labels     = label_encoder.fit_transform(self.dataset_true_labels['processType'])

        self.dataset = self.dataset.drop(['processType'], 1)
        self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]

        label_encoder   = LabelEncoder()
        true_labels     = label_encoder.fit_transform(self.dataset_true_labels['processType'])

        X_train, X_test, y_train, y_test = train_test_split(self.dataset, true_labels, test_size=0.3) # 70% training and 30% test

        logging.info(X_train)

        scaler = StandardScaler()
        pca = PCA(n_components = 2)

        X_std_train = scaler.fit_transform(X_train)
        X_std_train = pca.fit_transform(X_std_train)
        X_std_test = scaler.fit_transform(X_test)
        X_std_test = pca.fit_transform(X_std_test)


        svc = svm.SVC(kernel='rbf')
        model = svc.fit(X_std_train, y_train)
        predicted_labels = svc.predict(X_std_test)

        logging.info("Accuracy: {}".format(accuracy_score(y_test, predicted_labels)))

        # The equation of the separating plane is given by all x so that np.dot(svc.coef_[0], x) + b = 0.
        # Solve for w3 (z)
        # z = lambda x,y: (-model.intercept_[0]-model.coef_[0][0]*x -model.coef_[0][1]*y) / model.coef_[0][2]

        # tmp = np.linspace(-5,5,30)
        # x,y = np.meshgrid(tmp,tmp)

        # fig = plt.figure()
        # ax  = fig.add_subplot(111, projection='3d')
        # ax.plot3D(X_std_train[y_train==0,0], X_std_train[y_train==0,1], X_std_train[y_train==0,2],'ob')
        # ax.plot3D(X_std_train[y_train==1,0], X_std_train[y_train==1,1], X_std_train[y_train==1,2],'sr')
        # ax.plot_surface(x, y, z(x,y))
        # ax.view_init(30, 60)
        # plt.show()

        value=0.5
        width=0.25
        # Plot Decision Region using mlxtend's awesome plotting function
        ax = plot_decision_regions(X=X_std_train, 
                            y=y_train,
                            clf=model,
                            legend=2)

        # Update plot object with X/Y axis labels and Figure Title
        plt.xlabel("PCA 1", size=14)
        plt.ylabel("PCA 2", size=14)
        plt.title('SVM Decision Region Boundary', size=16)

        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, 
                ['Benign', 'Malware'], 
                framealpha=0.3, scatterpoints=1)

        plt.show()
        plt.savefig(os.path.join(workingDirectory, 'resources\\resultplt.png'))
    
        knn = KNeighborsClassifier(n_neighbors=2)
        knn.fit(X_std_train, y_train)
        y_pred = knn.predict(X_std_test)
        logging.info("KNN Accuracy: {}".format(accuracy_score(y_pred, predicted_labels)))

         
        value=1.5
        width=0.75

        ax = plot_decision_regions(X_std_train, y_train, 
                                    clf=knn, 
                                    filler_feature_values={2: value, 3:value, 4:value, 5:value},
                                    filler_feature_ranges={2: width, 3: width, 4:width, 5:width},
                                    legend=2)# Adding axes annotations
        plt.xlabel("PCA 1", size=14)
        plt.ylabel("PCA 2", size=14)
        plt.title('KNN Decision Region Boundary', size=16)
        # plt.title('Knn with K='+ str(2))

        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, 
                ['Benign', 'Malware'], 
                framealpha=0.3, scatterpoints=1)

        plt.show()