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
import matplotlib.pyplot as plt
import numpy as np
import logging
import pandas as pd
import sys
import seaborn as sns

from cmath import pi
from random import shuffle
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn import svm

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)


class CortusModel:
    model           = None
    dataset         = None
    stringVocab     = None
    sectionVocab    = None
    importLibVocab  = None
    relocationVocab = None
    importNameVocab = None

    def __init__(self, dataset, flag=None):
        logging.info("Creating Cortus Malware Analysis Model")
        self.dataset = pd.read_csv(dataset, sep=',', low_memory=False, index_col=[0] )
        self.dataset = self.dataset.dropna(axis=1, how='all')
        self.dataset = self.dataset.fillna(0)
        self.dataPreProcessing()
        self.lshPreProcessing()
        self.createModel()


    def dataPreProcessing(self) :
        # Find counts of level of permissions
        logging.info("Processing Dataset")
        self.dataset[self.dataset.filter(regex='_perms').columns] = self.dataset[self.dataset.filter(regex='_perms').columns].apply(lambda col:(pd.Categorical(col).codes))
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset[self.dataset.filter(regex='_perms').columns].stack().groupby(level=0).value_counts().unstack(fill_value=0).add_prefix("permissionCount_"))], axis=1)
        self.dataset = self.dataset.drop(self.dataset.filter(regex='_perms').columns, axis=1)

        # Grab count of interesting memory sections per process dump
        self.dataset = self.dataset.drop(self.dataset.filter(regex='Memory_Section').columns, axis=1)
        dataUniqueMemorySectionCount = self.dataset[self.dataset.filter(regex='_size').columns].gt(0).sum(axis=1)
        self.dataset['uniqueMemorySectionCount'] = dataUniqueMemorySectionCount
        self.dataset = self.dataset.drop(self.dataset.filter(regex='_size').columns, axis=1)

        # Clean up string data into categorical data
        self.dataset['processType'] = pd.Categorical(self.dataset['processType']).codes
        self.dataset['arch'] = pd.Categorical(self.dataset['arch']).codes
        self.dataset['bits'] = pd.Categorical(self.dataset['bits']).codes
        self.dataset['canary'] = pd.Categorical(self.dataset['canary']).codes
        self.dataset['retguard'] = pd.Categorical(self.dataset['retguard']).codes
        self.dataset['crypto'] = pd.Categorical(self.dataset['crypto']).codes
        self.dataset['endian'] = pd.Categorical(self.dataset['endian']).codes
        self.dataset['flags'] = pd.Categorical(self.dataset['flags']).codes
        self.dataset['havecode'] = pd.Categorical(self.dataset['havecode']).codes
        self.dataset['machine'] = pd.Categorical(self.dataset['machine']).codes
        self.dataset['static'] = pd.Categorical(self.dataset['static']).codes

        self.dataset_true_labels = self.dataset[['processType', 'processName']]
        self.dataset = self.dataset.drop(['processType', 'processName'], 1)


    def lshPreProcessing(self) :
        logging.info("Creating LSH Hashes and Vocabs")
        # Convert to the equivalent of our "Shingles" (We can use the full words except for strings)
        self.dataset['sectionContentFull']    = self.dataset['sectionContentFull'].apply(ast.literal_eval)
        self.dataset['stringContentFull']     = self.dataset['stringContentFull'].apply(ast.literal_eval)
        self.dataset['relocationContentFull'] = self.dataset['relocationContentFull'].apply(ast.literal_eval)
        self.dataset['importNameContentFull'] = self.dataset['importNameContentFull'].apply(ast.literal_eval)
        self.dataset['importLibContentFull']  = self.dataset['importLibContentFull'].apply(ast.literal_eval)

        self.sectionVocab    = set().union(*self.dataset['sectionContentFull'])
        self.stringVocab     = set().union(*self.dataset['stringContentFull'])
        self.importLibVocab  = set().union(*self.dataset['importLibContentFull'])
        self.relocationVocab = set().union(*self.dataset['relocationContentFull'])
        self.importNameVocab = set().union(*self.dataset['importNameContentFull'])
        
        sectionList = []
        for index, value in self.dataset['sectionContentFull'].items() :
            valueList = [1 if x in value else 0 for x in self.sectionVocab]
            sectionList.append(valueList)

        stringList = []
        for index, value in self.dataset['stringContentFull'].items() :
            valueList = [1 if x in value else 0 for x in self.stringVocab]
            stringList.append(valueList)

        relocList = []
        for index, value in self.dataset['relocationContentFull'].items() :
            valueList = [1 if x in value else 0 for x in self.relocationVocab]
            relocList.append(valueList)

        importNameList = []
        for index, value in self.dataset['importNameContentFull'].items() :
            valueList = [1 if x in value else 0 for x in self.importNameVocab]
            importNameList.append(valueList)

        importLibList = []
        for index, value in self.dataset['importLibContentFull'].items() :
            valueList = [1 if x in value else 0 for x in self.importLibVocab]
            importLibList.append(valueList)

        self.dataset['stringContentEncoding']     = stringList
        self.dataset['sectionContentEncoding']    = sectionList
        self.dataset['importLibContentEncoding']  = importLibList
        self.dataset['relocationContentEncoding'] = relocList
        self.dataset['importNameContentEncoding'] = importNameList

        section_minhash    = self.build_minhash_func(len(self.sectionVocab), 20)
        string_minhash     = self.build_minhash_func(len(self.stringVocab), 20)
        reloc_minhash      = self.build_minhash_func(len(self.relocationVocab), 20)
        importName_minhash = self.build_minhash_func(len(self.importNameVocab), 20)
        importLib_minhash  = self.build_minhash_func(len(self.importLibVocab), 20)

        self.dataset['sectionHash'] = self.dataset['sectionContentEncoding'].apply(lambda x: self.create_hash(self.sectionVocab, x, section_minhash))
        self.dataset['stringHash']  = self.dataset['stringContentEncoding'].apply(lambda x: self.create_hash(self.stringVocab, x, string_minhash))
        self.dataset['relocationHash'] = self.dataset['relocationContentEncoding'].apply(lambda x: self.create_hash(self.relocationVocab, x, reloc_minhash))
        self.dataset['importNameHash'] = self.dataset['importNameContentEncoding'].apply(lambda x: self.create_hash(self.importNameVocab, x, importName_minhash))
        self.dataset['importLibHash']  = self.dataset['importLibContentEncoding'].apply(lambda x: self.create_hash(self.importLibVocab, x, importLib_minhash))

        self.dataset = self.dataset.drop(['sectionContentEncoding', 'stringContentEncoding', 'relocationContentEncoding', 'importNameContentEncoding', 'importLibContentEncoding'], 1)
        self.dataset = self.dataset.drop(['sectionContentFull', 'stringContentFull', 'relocationContentFull', 'importNameContentFull', 'importLibContentFull'], 1)
      
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset['sectionHash'].tolist())], axis=1)
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset['stringHash'].tolist())], axis=1)
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset['relocationHash'].tolist())], axis=1)
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset['importNameHash'].tolist())], axis=1)
        self.dataset = pd.concat([self.dataset, pd.DataFrame(self.dataset['importLibHash'].tolist())], axis=1)

        self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]


    def create_hash_func(self, size):
        # function for creating the hash vector/function
        hash_ex = list(range(1, size+1))
        shuffle(hash_ex)
        return hash_ex

    def build_minhash_func(self, vocab_size, nbits):
        # function for building multiple minhash vectors
        hashes = []
        for _ in range(nbits):
            hashes.append(self.create_hash_func(vocab_size))
        return hashes

    def create_hash(self, vocab, vector, minhash_func):
        # use this function for creating our signatures (eg the matching)
        signature = []
        for func in minhash_func:
            for i in range(1, len(vocab)+1):
                idx = func.index(i)
                print(vector)
                signature_val = vector[idx]
                if signature_val == 1:
                    signature.append(idx)
                    break
        return signature

    def make_meshgrid(self, x, y, h=.02):
        x_min, x_max = x.min() - 1, x.max() + 1
        y_min, y_max = y.min() - 1, y.max() + 1
        xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))
        return xx, yy

    def plot_contours(self, ax, clf, xx, yy, **params):
        Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])
        Z = Z.reshape(xx.shape)
        out = ax.contourf(xx, yy, Z, **params)
        return out

    def createPipeline(self):
        preprocessor = Pipeline(
        [("scaler", StandardScaler()),
         ("pca", PCA(n_components=2, random_state=42))]
        )
        classifier = Pipeline(
        [( "SVC",
            svm.SVC(kernel='rbf'))]
        )
        clusterer = Pipeline(
        [("KNN",
           KMeans(n_clusters=2))]
        )
        pipe = Pipeline(
        [("preprocessor", preprocessor),
         ("clusterer", classifier)]
        )

        return preprocessor, classifier, clusterer, pipe

    def createModel(self):
        logging.info("Training and Testing Model")
        X_train, X_test, y_train, y_test = train_test_split(self.dataset, self.dataset_true_labels['processType'], test_size=0.3) # 70% training and 30% test
        preprocessor, classifier, clusterer, pipe = self.createPipeline()

        label_encoder   = LabelEncoder()
        true_labels     = label_encoder.fit_transform(self.dataset_true_labels['processType'])
        classifierModel = pipe.fit(X_train, y_train)

        preprocessed_data = pipe["preprocessor"].transform(X_test)
        predicted_labels  = pipe["clusterer"]["SVC"].predict(preprocessed_data)

        print("Accuracy:", accuracy_score(y_test, predicted_labels))

        fig, ax = plt.subplots()
        title = ('Decision surface of RBF SVC ')
        X0, X1 = preprocessed_data[:, 0], preprocessed_data[:, 1]
        xx, yy = self.make_meshgrid(X0, X1)

        self.plot_contours(ax, pipe["clusterer"]["SVC"], xx, yy, cmap=plt.cm.coolwarm, alpha=0.8)
        ax.scatter(X0, X1, c=y_test, cmap=plt.cm.coolwarm, s=20, edgecolors='k')
        ax.set_ylabel('PCA Component 1')
        ax.set_xlabel('PCA Component 2')
        ax.set_xticks(())
        ax.set_yticks(())
        ax.set_title(title)
        ax.legend()
        plt.show()