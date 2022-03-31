# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor used as a form of EDA for the wider machine learning model
# Focuses on the creation of usable and quantifiable data derived through the use of radare2 on process memory dumps
# ------------------------------------------------------------------------------------------------------------------

import argparse
import json
import pandas as pd
import pprint
import sys
import typing

from featureExtractor import MemoryFeatureExtractor

# --------------------------------------------------------------------------------------------
# // Utility Functions
# Collection of functions that peform tasks generalised across the feature processes
# --------------------------------------------------------------------------------------------
def flattenDataFrame(nestedDataFrame) :
    flattenedDataFrame = nestedDataFrame.apply(lambda x: pd.Series(x.dropna().to_numpy())).iloc[[0]]
    flattenedDataFrame = flattenedDataFrame.T

    return flattenedDataFrame


def blockPrint():
    sys.stdout = open(os.devnull, 'w')


def enablePrint():
    sys.stdout = sys.__stdout__


# --------------------------------------------------------------------------------------------
# // Feature Extraction Process Starter
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with collation of features
def main(argv) :
    benignInputFolder      = None
    maliciousInputFolder   = None
    benignOutputFolder     = None
    maliciousOutputFolder  = None

    parser = argparse.ArgumentParser(description='Create a number of features from provided process memory dumps')
    parser.add_argument('--iBenFolder', dest='inputBenignFolder', help='The input folder for benign process dumps')
    parser.add_argument('--oBenFolder', dest='benignOutputFolder', help='The input folder for benign process dumps')
    parser.add_argument('--iMalFolder', dest='maliciousInputFolder', help='The input folder for benign process dumps')
    parser.add_argument('--oMalFolder', dest='maliciousOutputFolder', help='The input folder for benign process dumps')

    args = parser.parse_args()
    featureExtractor = MemoryFeatureExtractor(args.inputBenignFolder, args.benignOutputFolder, args.maliciousInputFolder, args.maliciousOutputFolder)

if __name__ == "__main__":
    main(sys.argv[1:])
