import numpy as np
import os
import pandas as pd
import seaborn as sns

from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import SelectKBest, f_regression

class DatasetAnalyser :
    dataset       = None
    datasetLabels = None

    def __init__(self, dataset) :
        self.dataset = dataset
        self.datasetLabels = self.dataset[['processType']]

        self.analyzeDataset()

    def analyzeDataset(self, dataset) :

        label_encoder     = LabelEncoder()
        true_labels       = label_encoder.fit_transform(self.datasetLabels['processType'])

        feature_selector = SelectKBest(f_regression, k = "all")
        fit = feature_selector.fit(self.dataset, true_labels)

        p_values = pd.DataFrame(fit.pvalues_)
        scores = pd.DataFrame(fit.scores_)
        input_variable_names = pd.DataFrame(self.dataset.columns)
        summary_stats = pd.concat([input_variable_names, p_values, scores], axis = 1)
        summary_stats.columns = ["input_variable", "p_value", "f_score"]
        summary_stats.sort_values(by = "p_value", inplace = True)

        p_value_threshold = 0.05
        score_threshold = 5
        selected_variables = summary_stats.loc[(summary_stats["f_score"] >= score_threshold) &
                                            (summary_stats["p_value"] <= p_value_threshold)]
        selected_variables = selected_variables["input_variable"].tolist()

        summary_stats.to_csv(os.path.join(os.fsdecode(self.outFolder), 'datasetsummary.csv'))
