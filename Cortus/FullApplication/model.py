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
import PySimpleGUI as sg
import sys
import seaborn as sns

from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler, MaxAbsScaler
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.neighbors import KNeighborsClassifier
from mlxtend.plotting import plot_decision_regions

np.set_printoptions(threshold=sys.maxsize)
logging.basicConfig(level=logging.INFO)
workingDirectory = os.path.dirname(os.path.abspath(__file__))
iconImg = os.path.join(workingDirectory, 'resources\CortusLogoTask.png')


class CortusModel:
    # Define the model, dataset and outpath for saving
    #-- Options and Built Models --
    model             = None
    modelParameters   = None

    #-- Datasets and OutFolder --
    dataset           = None
    datasetLabels     = None
    outFolder         = None

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
        self.dataset = self.dataset[self.dataset.T[self.dataset.dtypes!=np.object].index]

        self.createModelLayout()


    def createModelLayout(self) :
        # sg.set_options(text_justification='right')      

        svmInput = [
                    [sg.Text('Kernel Type', size=(15, 1))],    
                    [sg.Radio('Linear', 'kernel', size=(12, 1),),   
                     sg.Radio('Poly', 'kernel', size=(12, 1))],
                    [sg.Radio('RBF', 'kernel', size=(12, 1)),   
                     sg.Radio('sigmoid', 'kernel', size=(12, 1))],
                    [sg.Text('Coef', size=(15, 1)), sg.In(default_text='0.0', size=(10, 1)),
                     sg.Text('Degree Poly Kernel', size=(15, 1)), sg.Spin(values=[i for i in range(0, 1000)], initial_value=0, size=(6, 1)),]   
                   ]  

        knnInput = [
                    [sg.Text('Weights Type', size=(15, 1))],    
                    [sg.Radio('Uniform', 'Weights', size=(12, 1), default=True),   
                     sg.Radio('Distance', 'Weights', size=(12, 1))],
                    [sg.Text('Algorithm Type', size=(15, 1))],    
                    [sg.Radio('Auto', 'Algorithm', size=(12, 1), default=True),   
                     sg.Radio('Ball_tree', 'Algorithm', size=(12, 1))],
                    [sg.Radio('Kd_tree', 'Algorithm', size=(12, 1), default=True),   
                     sg.Radio('Brute', 'Algorithm', size=(12, 1))],
                    [sg.Text('Number of Neighbours', size=(15, 1)), sg.Spin(values=[i for i in range(0, 1000)], initial_value=0, size=(6, 1)),]
                   ]  

        optimalInput = [
                     [sg.Text('Optimised Model Type', size=(15, 1))],    
                     [sg.Radio('SVM', 'model', size=(12, 1), default=True, k='-SVM-', enable_events=True),   
                      sg.Radio('KNN', 'model', size=(12, 1), k='-KNN-', enable_events=True)], 
                    ]      

        layout = [
                  [sg.Text('Model Parameters and Setup', font=('Helvetica', 16))],
                  [sg.HorizontalSeparator()],      
                  [sg.Text('Model Type', size=(15, 1))],      
                  [sg.Radio('SVM', 'model', size=(12, 1), default=True, k='-SVM-', enable_events=True),   
                   sg.Radio('KNN', 'model', size=(12, 1), k='-KNN-', enable_events=True)],
                  [sg.Radio('Gausian', 'model', size=(12, 1), k='-GAUS-', enable_events=True),   
                   sg.Radio('Ensemble', 'model', size=(12, 1))],   
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC1-'), sg.T('SVM Parameters', enable_events=True, text_color='white', k='-OPEN SEC1-TEXT')],
                  [self.collapse(svmInput, '-SEC1-')],
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC2-'), sg.T('KNN Parameters', enable_events=True, text_color='white', k='-OPEN SEC2-TEXT')],
                  [self.collapse(knnInput, '-SEC2-')],
                  [sg.HorizontalSeparator()],
                  [sg.T(self.SYMBOL_DOWN, enable_events=True, k='-OPEN SEC3-'), sg.T('Gaus Parameters', enable_events=True, text_color='white', k='-OPEN SEC3-TEXT')],
                  [self.collapse(optimalInput, '-SEC3-')],
                  [sg.HorizontalSeparator()],
                  [sg.Submit('CreateModel'), sg.Button('Exit')]
                 ]    

        window = sg.Window('Cortus Machine Learning Model', layout, font=("Helvetica", 12)) 

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
            if event.startswith('-OPEN SEC3-') or event.startswith('-GAUS-'):
                opened3 = not opened3
                window['-OPEN SEC3-'].update(self.SYMBOL_DOWN if opened3 else self.SYMBOL_UP)
                window['-SEC3-'].update(visible=opened3)
            if event.startswith('CreateModel'):
                model = values['model']
                print(model)


    def createModel(self, dataset, parametersDict):
        logging.info("Training and Testing Model")

        label_encoder   = LabelEncoder()
        true_labels     = label_encoder.fit_transform(self.dataset_true_labels['processType'])
        X_train, X_test, y_train, y_test = train_test_split(self.dataset, true_labels, test_size=0.3) # 70% training and 30% test

        scaler = StandardScaler()
        pca = PCA(n_components = 2)

        X_std_train = scaler.fit_transform(X_train)
        X_std_train = pca.fit_transform(X_std_train)
        X_std_test = scaler.fit_transform(X_test)
        X_std_test = pca.fit_transform(X_std_test)


    def svmModel(self, X_train, X_test, Y_train, Y_test) :

        svc = svm.SVC(kernel='rbf')
        model = svc.fit(X_train, Y_train)
        predicted_labels = svc.predict(X_test)

        logging.info("Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))


    def knnModel(self, X_train, X_test, Y_train, Y_test) :

        knn = KNeighborsClassifier(n_neighbors=2)
        knn.fit(X_train, Y_train)
        predicted_labels = knn.predict(X_test)
        logging.info("KNN Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))


    def optimisedModel(self, X_train, X_test, Y_train, Y_test) :

        svc = svm.SVC(kernel='rbf')
        model = svc.fit(X_train, Y_train)
        predicted_labels = svc.predict(X_test)

        logging.info("Accuracy: {}".format(accuracy_score(Y_test, predicted_labels)))


    def plotResults(self, model, X_train, X_test, Y_train, Y_test) :

        # The equation of the separating plane is given by all x so that np.dot(svc.coef_[0], x) + b = 0.
        # Solve for w3 (z)
        z = lambda x,y: (-model.intercept_[0]-model.coef_[0][0]*x -model.coef_[0][1]*y) / model.coef_[0][2]

        tmp = np.linspace(-5,5,30)
        x,y = np.meshgrid(tmp,tmp)

        fig = plt.figure()
        ax  = fig.add_subplot(111, projection='3d')
        ax.plot3D(X_std_train[y_train==0,0], X_std_train[y_train==0,1], X_std_train[y_train==0,2],'ob')
        ax.plot3D(X_std_train[y_train==1,0], X_std_train[y_train==1,1], X_std_train[y_train==1,2],'sr')
        ax.plot_surface(x, y, z(x,y))
        ax.view_init(30, 60)
        plt.show()

        value=0.5
        width=0.25
        # Plot Decision Region using mlxtend's awesome plotting function
        ax = plot_decision_regions(X=X_std_train, y=y_train, clf=model, legend=2)

        # Update plot object with X/Y axis labels and Figure Title
        plt.xlabel("PCA 1", size=14)
        plt.ylabel("PCA 2", size=14)
        plt.title('SVM Decision Region Boundary', size=16)
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, 
                ['Benign', 'Malware'], 
                framealpha=0.3, scatterpoints=1)
        plt.show()
    
        ax = plot_decision_regions(X_std_train, y_train, clf=model, filler_feature_values={2: value, 3:value, 4:value, 5:value},filler_feature_ranges={2: width, 3: width, 4:width, 5:width}, legend=2)# Adding axes annotations

        plt.xlabel("PCA 1", size=14)
        plt.ylabel("PCA 2", size=14)
        plt.title('KNN Decision Region Boundary', size=16)
        plt.title('Knn with K='+ str(2))
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles, 
                ['Benign', 'Malware'], 
                framealpha=0.3, scatterpoints=1)
        plt.show()

        plt.savefig(os.path.join(workingDirectory, 'resources\\resultplt.png'))

        
    def collapse(self, layout, key):
        """
        Helper function that creates a Column that can be later made hidden, thus appearing "collapsed"
        :param layout: The layout for the section
        :param key: Key used to make this seciton visible / invisible
        :return: A pinned column that can be placed directly into your layout
        :rtype: sg.pin
        """
        return sg.pin(sg.Column(layout, key=key,  visible=False))