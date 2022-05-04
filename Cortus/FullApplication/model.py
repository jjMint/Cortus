# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# The Cortus Model
#
# The purpose of this file is to contain all functions and methods associated with the development
# training and storage of the trained Cortus model
# ------------------------------------------------------------------------------------------------------------------
import ast
import json
import matplotlib.pyplot as plt
import numpy as np
import os
import pandas as pd
import sys
import sklearn
import seaborn as sns

from random import shuffle
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score, accuracy_score
from sklearn.preprocessing import OneHotEncoder, OrdinalEncoder, LabelEncoder, LabelBinarizer, MultiLabelBinarizer, MinMaxScaler, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn import svm

np.set_printoptions(threshold=sys.maxsize)


class CortusModel:

    model       = None
    extractor   = None
    dataset     = None


    def __init__():
        test = None


    def make_meshgrid(x, y, h=.02):
        x_min, x_max = x.min() - 1, x.max() + 1
        y_min, y_max = y.min() - 1, y.max() + 1
        xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))
        return xx, yy

    def plot_contours(ax, clf, xx, yy, **params):
        Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])
        Z = Z.reshape(xx.shape)
        out = ax.contourf(xx, yy, Z, **params)
        return out

    def createPipeline(self):
        preprocessor = Pipeline(
            [
                ("scaler", StandardScaler()),
                ("pca", PCA(n_components=2, random_state=42)),
            ]
        )

        classifier = Pipeline(
        [
            (
                "SVC",
                svm.SVC(kernel='rbf')
            ),
        ]
        )

        clusterer = Pipeline(
            [
            (
                "KNN",
                KMeans(n_clusters=2)
            )
            ]
        )

        pipe = Pipeline(
            [
                ("preprocessor", preprocessor),
                ("clusterer", clusterer)
            ]
        )

    def createModel(self):

        X_train, X_test, y_train, y_test = train_test_split(finalFrameV2, finalFrame_true_labels['processType'], test_size=0.3) # 70% training and 30% test

        label_encoder = LabelEncoder()
        true_labels = label_encoder.fit_transform(finalFrame_true_labels['processType'])
        clf = pipe.fit(X_train, y_train)

        preprocessed_data = pipe["preprocessor"].transform(X_test)
        predicted_labels = pipe["clusterer"]["KNN"].predict(preprocessed_data)

        print("Accuracy:", accuracy_score(y_test, predicted_labels))

        fig, ax = plt.subplots()
        # title for the plots
        title = ('Decision surface of RBF SVC ')
        # Set-up grid for plotting.
        X0, X1 = preprocessed_data[:, 0], preprocessed_data[:, 1]
        xx, yy = make_meshgrid(X0, X1)

        plot_contours(ax, pipe["clusterer"]["KNN"], xx, yy, cmap=plt.cm.coolwarm, alpha=0.8)
        ax.scatter(X0, X1, c=y_test, cmap=plt.cm.coolwarm, s=20, edgecolors='k')
        ax.set_ylabel('PCA Component 1')
        ax.set_xlabel('PCA Component 2')
        ax.set_xticks(())
        ax.set_yticks(())
        ax.set_title(title)
        ax.legend()
        plt.show()