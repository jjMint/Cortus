# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory Feature Extractor used as a form of EDA for the wider machine learning model
# Focuses on the creation of usable and quantifiable data derived through the use of radare2 on process memory dumps
# ------------------------------------------------------------------------------------------------------------------

import getopt
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

# --------------------------------------------------------------------------------------------
# // Process Feature Collator
# --------------------------------------------------------------------------------------------
# Class that handles input and output pathing along with collation of features
class featureCollator :
    outputFolder   = None

    def __init__(self, inputFolder, outputFolder):
        self.inputFolder    = inputFolder
        self.outputFolder   = outputFolder


def main(argv) :
    benignInputFolder      = None
    maliciousInputFolder   = None
    benignOutputFolder     = None
    maliciousOutputFolder  = None

    try :
        opts, args = getopt.getopt(argv, "hi:o", ["iBenignFolder=", "oBenignFolder=", "iMaliciousFolder=", "oMaliciousFolder="])
    except getopt.GetoptError :
        print("Please provide and input and ouput folder location: featureExtractor.py -i <inputBenignFolder> -o <outputBenignFolder> -b <inputMaliciousFolder> -g <outputMaliciousFolder>")
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-h':
            print("featureExtractor.py -i <inputBenignFolder> -o <outputBenignFolder> -b <inputMaliciousFolder> -g <outputMaliciousFolder>")
            sys.exit()
        elif opt in ("-i", "--iBenignFolder"):
            benignInputFolder = arg
        elif opt in ("-o", "--oBenignFolder"):
            benignOutputFolder = arg
        elif opt in ("-b", "--iMaliciousFolder"):
            maliciousInputFolder = arg
        elif opt in ("-g", "--oMaliciousFolder"):
            maliciousOutputFolder = arg

    featureExtractor = MemoryFeatureExtractor(benignInputFolder, benignOutputFolder, maliciousInputFolder, maliciousOutputFolder)

if __name__ == "__main__":
    main(sys.argv[1:])


