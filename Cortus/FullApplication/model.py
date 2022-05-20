# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# The Cortus Model
#
# The purpose of this file is to contain all functions and methods associated with the development
# training and storage of the trained Cortus model
# ------------------------------------------------------------------------------------------------------------------
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

import matplotlib.pyplot as plt
import numpy as np
import logging
import os
import pandas as pd
import pickle
import PySimpleGUI as sg
import sys

from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, average_precision_score, plot_confusion_matrix, plot_precision_recall_curve, classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import RandomizedSearchCV
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.neighbors import KNeighborsClassifier
from mlxtend.plotting import plot_decision_regions

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))
iconImg = os.path.join(workingDirectory, 'resources\CortusLogoTask.png')


class CortusModelCreator:
    # Define the model, dataset and outpath for saving
    #-- Datasets and OutFolder --
    dataset           = None
    datasetLabels     = None

    #-- UI STUFF -- 
    SYMBOL_UP =    '▲'
    SYMBOL_DOWN =  '▼'


    def __init__(self, dataset):
        logging.info("Creating Cortus Malware Analysis Model")
        self.dataset = pd.read_pickle(dataset)

        # Extra cleaning and label separation
        self.dataset = self.dataset.reset_index(drop=True)
        self.dataset_true_labels = self.dataset[['processType']]
        self.dataset = self.dataset.drop(['processType'], 1)
        # self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]

        self.createModelLayout()


    def createModelLayout(self) :
        svmInput = [
                    [sg.Text('Kernel Type', size=(15, 1))],    
                    [sg.Radio('Linear', 'kernel', size=(12, 1), k='linear'),   
                     sg.Radio('Poly', 'kernel', size=(12, 1), k='Poly')],
                    [sg.Radio('RBF', 'kernel', size=(12, 1), k='RBF'),   
                     sg.Radio('sigmoid', 'kernel', size=(12, 1), k='sigmoid')],
                    [sg.Text('Coef', size=(15, 1)), sg.In(default_text='0.5', size=(10, 1), k='coef'),
                     sg.Text('Degree Poly Kernel', size=(15, 1)), sg.Spin(values=[i for i in range(0, 1000)], initial_value=3, size=(6, 1), k='polyAmount'),]   
                   ]  

        knnInput = [
                    [sg.Text('Weights Type', size=(15, 1))],    
                    [sg.Radio('Uniform', 'Weights', size=(12, 1), k='Uniform'),   
                     sg.Radio('Distance', 'Weights', size=(12, 1), k='Distance')],
                    [sg.Text('Algorithm Type', size=(15, 1))],    
                    [sg.Radio('Auto', 'Algorithm', size=(12, 1), k='Auto'),   
                     sg.Radio('Ball_tree', 'Algorithm', size=(12, 1), k='Ball_tree')],
                    [sg.Radio('Kd_tree', 'Algorithm', size=(12, 1), k='Kd_tree'),   
                     sg.Radio('Brute', 'Algorithm', size=(12, 1), k='Brute')],
                    [sg.Text('Number of Neighbours', size=(15, 1), k='Neighbours'), sg.Spin(values=[i for i in range(0, 1000)], initial_value=0, size=(6, 1), k='degree'),]
                   ]  

        optimalInput = [
                     [sg.Text('Optimised Model Type', size=(20, 1))],    
                     [sg.Radio('SVM', 'modelType', size=(12, 1), k='-SVMO-'),   
                      sg.Radio('KNN', 'modelType', size=(12, 1), k='-KNNO-')], 
                    ]      

        layout = [
                  [sg.Text('Model Parameters and Setup', font=('Helvetica', 16))],
                  [sg.HorizontalSeparator()],      
                  [sg.Text('Model Type', size=(15, 1))],      
                  [sg.Radio('SVM', 'model', size=(12, 1), default=True, k='-SVM-', enable_events=True),   
                   sg.Radio('KNN', 'model', size=(12, 1), k='-KNN-', enable_events=True),
                  sg.Radio('Optimised', 'model', size=(12, 1), k='-OPT-', enable_events=True)],   
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC1-'), sg.T('SVM Parameters', enable_events=True, text_color='white', k='-OPEN SEC1-TEXT')],
                  [self.collapse(svmInput, '-SEC1-')],
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC2-'), sg.T('KNN Parameters', enable_events=True, text_color='white', k='-OPEN SEC2-TEXT')],
                  [self.collapse(knnInput, '-SEC2-')],
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC3-'), sg.T('Optimal Parameters', enable_events=True, text_color='white', k='-OPEN SEC3-TEXT')],
                  [self.collapse(optimalInput, '-SEC3-')],
                  [sg.HorizontalSeparator()],
                  [sg.Submit('CreateModel'), sg.Button('Exit')]
                 ]    

        window = sg.Window('Cortus Machine Learning Model', layout, font=("Helvetica", 12), size=(800, 900)) 

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
            if event.startswith('-OPEN SEC2-') or event.startswith('-KNN-'):
                opened2 = not opened2
                window['-OPEN SEC2-'].update(self.SYMBOL_DOWN if opened2 else self.SYMBOL_UP)
                window['-SEC2-'].update(visible=opened2)
            if event.startswith('-OPEN SEC3-') or event.startswith('-OPT-'):
                opened3 = not opened3
                window['-OPEN SEC3-'].update(self.SYMBOL_DOWN if opened3 else self.SYMBOL_UP)
                window['-SEC3-'].update(visible=opened3)
            if event.startswith('CreateModel'):
                modelParams = {}
                if values['-SVM-'] :
                    modelParams['modelType'] = "svm"
                    modelParams['coef'] = values['coef']
                    if values['linear'] == 1:
                        modelParams['kernelType'] = 'linear'
                    elif values['Poly'] == 1:
                        modelParams['kernelType'] = 'poly'
                        modelParams['polyAmount'] =  values['polyAmount']
                    elif values['RBF'] == 1:
                        modelParams['kernelType'] = 'rbf'
                    elif values['sigmoid'] == 1:
                        modelParams['kernelType'] = 'poly'
                    self.createModel(modelParams)

                elif values['-KNN-'] :
                    modelParams['modelType'] = "knn"
                    modelParams['degree'] = values['degree']
                    if values['Uniform'] == 1:
                        modelParams['weights'] = 'uniform'
                    elif values['Distance'] == 1:
                        modelParams['weights'] = 'distance'
                    if values['Auto'] == 1:
                        modelParams['algo'] = 'auto'
                    elif values['Ball_tree'] == 1:
                        modelParams['algo'] = 'ball_tree'
                    elif values['Kd_tree'] == 1:
                        modelParams['algo'] = 'kd_tree'
                    elif values['Brute'] == 1:
                        modelParams['algo'] = 'brute'
                    self.createModel(modelParams)

                elif values['-OPT-'] :
                    modelParams['modelType'] = "opt"
                    if values['-KNNO-'] :
                        modelParams['optType'] = 'knn'
                    elif values['-SVMO-'] :
                        modelParams['optType'] = 'svm'
                    self.createModel(modelParams)


    def createModel(self, parametersDict):
        logging.info("Training and Testing Model")

        label_encoder   = LabelEncoder()
        true_labels     = label_encoder.fit_transform(self.dataset_true_labels['processType'])
        X_train, X_test, y_train, y_test = train_test_split(self.dataset, true_labels, test_size=0.3, random_state=43)  # 70% training and 30% test

        scaler = StandardScaler()
        pca    = PCA(n_components = 3)

        X_std_train = scaler.fit_transform(X_train)
        X_std_train = pca.fit_transform(X_std_train)
        X_std_test = scaler.fit_transform(X_test)
        X_std_test = pca.fit_transform(X_std_test)

        if (parametersDict['modelType']) == 'svm' :
            self.svmModel(X_std_train, X_std_test, y_train, y_test, parametersDict )
        if (parametersDict['modelType']) == 'knn' :
            self.knnModel(X_std_train, X_std_test, y_train, y_test, parametersDict )
        if (parametersDict['modelType']) == 'opt' :
            self.optimisedModel(X_std_train, X_std_test, y_train, y_test, parametersDict )

        self.saveModel('resources\\Cortus_PCA.pkl', pca)
        self.saveModel('resources\\Cortus_Scaler.pkl', scaler)
        self.saveModel('resources\\Cortus_SetColumns.pkl', self.dataset.columns)


    def svmModel(self, X_train, X_test, Y_train, Y_test, parametersDict) :
        resultsDict = {}

        if 'polyAmount' in parametersDict :
            svc = svm.SVC(kernel=parametersDict['kernelType'], coef0=float(parametersDict['coef']), degree=float(parametersDict['polyAmount']))
        else :
            svc = svm.SVC(kernel=parametersDict['kernelType'], coef0=float(parametersDict['coef']))
        model = svc.fit(X_train, Y_train)
        predicted_labels = model.predict(X_test)
        logging.info("SVM Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))

        resultsDict['Accuracy']          = accuracy_score(Y_test, predicted_labels)
        resultsDict['Average Precision'] = average_precision_score(Y_test, predicted_labels)
        self.plotResults(model, X_train, X_test, Y_train, Y_test, predicted_labels, f"SVM with Kernel: {parametersDict['kernelType']}")
        self.resultsLayout(resultsDict)

        print(classification_report(Y_test, predicted_labels))
        resultsDict['Model'] = model
        resultsDict['resultImagePath'] = os.path.join(workingDirectory, f'resources\\resultplt{"SVM"}.png')
        self.saveModel('resources\\Cortus_SVMModel.pkl', resultsDict)


    def knnModel(self, X_train, X_test, Y_train, Y_test, parametersDict) :
        resultsDict = {}

        knn = KNeighborsClassifier(weights=parametersDict['weights'], algorithm=parametersDict['algo'], n_neighbors=int(parametersDict['degree']))
        model = knn.fit(X_train, Y_train)
        predicted_labels = model.predict(X_test)
        logging.info("KNN Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))

        print(classification_report(Y_test, predicted_labels))
        resultsDict['Accuracy']          = accuracy_score(Y_test, predicted_labels)
        resultsDict['Average Precision'] = average_precision_score(Y_test, predicted_labels)
        self.plotResults(model, X_train, X_test, Y_train, Y_test, predicted_labels, "KNN")
        self.resultsLayout(resultsDict)

        resultsDict['Model'] = model
        resultsDict['resultImagePath'] = os.path.join(workingDirectory, f'resources\\resultplt{"KNN"}.png')
        self.saveModel('resources\\Cortus_KNNModel.pkl', resultsDict)


    def optimisedModel(self, X_train, X_test, Y_train, Y_test, parametersDict) :
        resultsDict = {}
        modelType = parametersDict['optType']
        model = None

        if modelType == 'knn' :
            modelParamGrid = {}
            modelParamGrid['weights'] = ['uniform', 'distance']          
            modelParamGrid['algorithm'] = ['auto', 'ball_tree', 'kd_tree', 'brute'] 
            modelParamGrid['metric'] = ['euclidean', 'manhattan', 'chebyshev', 'minkowski'] 
            modelParamGrid['n_neighbors'] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                             16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
            modelParamGrid['leaf_size'] =   [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                             16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
            knn = KNeighborsClassifier(algorithm='auto', leaf_size=30, metric='minkowski', 
                                        metric_params=None, n_jobs=1, n_neighbors=30, p=2, weights='uniform')
            grid = RandomizedSearchCV(knn, modelParamGrid, cv=10, scoring='accuracy')
            grid.fit(X_train, Y_train)

            logging.info("KNN Best Score " + str(grid.best_score_))
            logging.info("KNN Best Params " + str(grid.best_params_))
            model = KNeighborsClassifier(algorithm=grid.best_params_['algorithm'], leaf_size=30, metric='minkowski', 
                                        metric_params=None, n_jobs=1, n_neighbors=grid.best_params_['n_neighbors'], p=2, weights=grid.best_params_['weights'])
            model.fit(X_train, Y_train)

        if modelType == 'svm' :
            modelParamGrid = {}
            modelParamGrid['kernel'] = ['linear', 'poly', 'rbf', 'sigmoid'] 
            modelParamGrid['coef0'] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
            modelParamGrid['degree'] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]        
            svmModel = svm.SVC(kernel='rbf', degree=3, gamma='scale')
            grid = RandomizedSearchCV(svmModel, modelParamGrid, cv=10, scoring='accuracy')
            grid.fit(X_train, Y_train)

            logging.info("SVM Best Score " + str(grid.best_score_))
            logging.info("SVM Best Params " + str(grid.best_params_))
            model = svm.SVC(kernel=grid.best_params_['kernel'], degree=grid.best_params_['degree'], gamma='scale', coef0=grid.best_params_['coef0'])
            model.fit(X_train, Y_train)

        modelName = "Optimal " + modelType.upper()
        predicted_labels = model.predict(X_test)
        logging.info("Opt Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))

        resultsDict['Accuracy']          = accuracy_score(Y_test, predicted_labels)
        resultsDict['Average Precision'] = average_precision_score(Y_test, predicted_labels)
        
        print(classification_report(Y_test, predicted_labels))
        self.plotResults(model, X_train, X_test, Y_train, Y_test, predicted_labels, f"{modelName}")
        self.resultsLayout(resultsDict)

        resultsDict['Model'] = model
        resultsDict['resultImagePath'] = os.path.join(workingDirectory, f'resources\\resultplt{modelName}.png')
        self.saveModel(f'resources\\Cortus_OPTModel{modelType.upper()}.pkl', resultsDict)


    def plotResults(self, model, X_train, X_test, Y_train, Y_test, predicted_labels, modelType) :
        fig, (ax1, ax2, ax3) = plt.subplots(nrows=1, ncols=3, figsize=(20,10))
        fig.suptitle('Model Results and Analysis', fontsize=16)

        # -------------Confusion and Precision Recall Region----------------------#
        #Create a figure object
        plot_confusion_matrix(model, X_test, Y_test, ax=ax1)

        ax1.set_title("Confusion Matrix")
        ax1.set_xlabel('Predicted labels')
        ax1.set_ylabel('True labels'); 
        ax1.xaxis.set_ticklabels(['Benign', 'Malware']) 
        ax1.yaxis.set_ticklabels(['Benign', 'Malware'])

        plot_precision_recall_curve(model, X_test, Y_test, ax=ax2)
        ax2.set_title("Precision Recall Curve")

        # -------------Decision Region----------------------#
        scatter_kwargs = {'s': 80, 'edgecolor': None, 'alpha': 0.7}
        contourf_kwargs = {'alpha': 0.2}
        scatter_highlight_kwargs = {'s': 120, 'label': 'Test data', 'alpha': 0.7}
        # Plotting decision regions
        value=-0.1
        width=10.0
        # Plot Decision Region using mlxtend's awesome plotting function
        ax3 = plot_decision_regions(X=X_train, y=Y_train,
                                    X_highlight=X_test,
                                    filler_feature_values={2: value}, 
                                    filler_feature_ranges={2: width}, 
                                    clf=model, legend=2, ax=ax3,
                                    scatter_kwargs=scatter_kwargs,
                                    contourf_kwargs=contourf_kwargs,
                                    scatter_highlight_kwargs=scatter_highlight_kwargs)

        # Update plot object with X/Y axis labels and Figure Title
        plt.xlabel("PCA 1", size=14)
        plt.ylabel("PCA 2", size=14)
        plt.title(f'{modelType} Decision Region Boundary', size=16)
        handles, labels = ax3.get_legend_handles_labels()
        ax3.legend(handles, 
                ['Benign', 'Malware', 'TestData'], 
                framealpha=0.3, scatterpoints=1)


        fig2 = plt.figure()
        fig2.suptitle('PCA Dataset 3D plot', fontsize=16)
        ax4 = fig2.add_subplot(111, projection='3d')
        colors = {
        0: '#3b4cc0',
        1: '#b40426',
        }
        colors = list(map(lambda x: colors[x], Y_train))
        ax4.scatter(X_train[:, 0], X_train[:, 1], X_train[:, 2], c=colors, marker='o')
        fig2.show()

        ax4.set_xlabel('PCA 1')
        ax4.set_ylabel('PCA 2')
        ax4.set_zlabel('PCA 3')

        plt.show(block=False)
        plt.savefig(os.path.join(workingDirectory, f'resources\\resultplt{modelType}.png'))


    def resultsLayout(self, resultsDict):
        resultsInput = [
                        [sg.Text('Test Set Results', font=60)], 
                        [sg.HorizontalSeparator()],   
                        [sg.Text(f"Test Set Accuracy: {round(resultsDict['Accuracy'], 4)}")],
                        [sg.Text(f"Test Set Precision: {round(resultsDict['Average Precision'], 4)}")],
                       ]  
        layout =       [
                        [sg.Text('Model Creation Results', font=('Helvetica', 16))],
                        [sg.HorizontalSeparator()],
                        [resultsInput],
                        [sg.Button('Exit')]
                       ]    

        window = sg.Window('Cortus Machine Learning Model', layout, font=("Helvetica", 12), size=(500, 500) ) 
        while True:
            event, values = window.read()
            if event == "Exit" or event == sg.WIN_CLOSED:
                window.close()
                break


    def saveModel(self, modelName, model) :
        filename = os.path.join(workingDirectory, modelName)
        with open(filename, 'wb') as modelFile:
            pickle.dump(model, modelFile)

        
    def collapse(self, layout, key):
        """
        Helper function that creates a Column that can be later made hidden, thus appearing "collapsed"
        :param layout: The layout for the section
        :param key: Key used to make this seciton visible / invisible
        :return: A pinned column that can be placed directly into your layout
        :rtype: sg.pin
        """
        return sg.pin(sg.Column(layout, key=key,  visible=False))