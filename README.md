# Cortus - Process Memory Analysis and Detection
Repository for Process Memory Analysis (Cortus) toolset
-------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------
## Introduction
---------------------------------------------------------
This repository concerns the install of Cuckoo and Radare2 along with the scripts used to generate process memory datasets and extract features from said process memory.

It also contains the code used to create a machine learning model of the extracted features as a proof of concept of the value derived from only process memory.

### PLEASE NOTE -> Advice is to run this application on Linux, it will work on Windows, by radare2 build process and runtime can be temperamental

---------------------------------------------------------
## Requirements
---------------------------------------------------------
- Must have radare2 and r2Env installed in order to perform feature extraction (https://github.com/radareorg/radare2) -> Follow this page or else the application will fail on feature extraction (https://book.rada.re/first_steps/windows_compilation.html)
```
git clone https://github.com/radareorg/radare2

Default Windows builds use MSVC, so run those .bat:

preconfigure.bat       REM setup python, meson, ninja
configure.bat          REM run meson b + vs project
make.bat               REM run ninja -C b
prefix\bin\radare2.exe
```

- Python libraries required are: Pandas, Sklearn, pickle, logging, PySimpleGui, Seaborn, numpy and threading, argparse, matplotlib
```
pip3 install  Pandas, Sklearn, pickle, logging, PySimpleGui, Seaborn, numpy and threading, argparse, matplotlib
```
- MDMP files to extract features from. Easiest way to gain this file type is a process dump using SysInternals ProcDump Tool https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
- This application was created to be used on Windows, as such the file path indicators '/' won't work on Linux so some images will be missing

---------------------------------------------------------
## Platform and Environment
---------------------------------------------------------
Concerns the Cuckoo and Radare installation scripts along with batch scripts that perform the following:
- Benign process startup and activity generation
- Process memory dumping and collection for the Benign Processes
- Process memory dumping and collection (for multi process dumping, script by Guy Leech - June 2016, is used)
- Process memory collection from malicious process using cuckoo
- Environment set-up and vm sourcing for cuckoo

---------------------------------------------------------
## Data
---------------------------------------------------------
Contains extracted memory dumps in python Pickle or CSV format. Also contains the final dataset used in the capstone demonstration

---------------------------------------------------------
## Cortus
---------------------------------------------------------
Concerns feature extraction and storage from the process memory datasets

The Cortus Application enables users to extract features from Process memory dumps in MDMP format and create machine learning models that can be used to determine whether or not a process is malicious using either the provided dataset under the Data folder, or through creation of their own.

---------------------------------------------------------
### Full Application
The full Cortus Application

![image](https://user-images.githubusercontent.com/48663333/169799109-2be3d60d-4abb-4f82-ba1a-6c77ee2153de.png)


- Contains all files required to run the application, only requirements for install are
- Must have radare2 and r2Env installed in order to perform feature extraction (https://github.com/radareorg/radare2)
- Python libraries required are: Pandas, Sklearn, pickle, logging, PySimpleGui, Seaborn, numpy and threading, argparse, matplotlib
```
pip3 install  Pandas, Sklearn, pickle, logging, PySimpleGui, Seaborn, numpy and threading, argparse, matplotlib
```
- To run the Cortus Application, use python3 cortus.py -> will open the SimpleGui application

#### Resources
- This folder contains example models, diagrams and the PCA / Scaler trained on the expected model format. In the event there is a format mismatch, retrain that model type with the example dataset provided in the Data format and re run a test format

#### Functions
- Create Model -> Create a model from a collated pickle dataset created through the 'Create and Pre-process Pickle Dataset function' and generate results and statistical information 

![image](https://user-images.githubusercontent.com/48663333/169799215-4803260c-988a-42dc-89ad-db24f7ff9eda.png)
![image](https://user-images.githubusercontent.com/48663333/169799068-70a54a80-7425-4936-9f40-10e4434b7558.png)

- Load and Test Model -> Provide a model from disk and a process dmp to be tested

![image](https://user-images.githubusercontent.com/48663333/169799251-7fdaa9ee-7383-403a-8ccc-edaf013e1fd1.png)
![image](https://user-images.githubusercontent.com/48663333/169799269-9573b578-7e40-4f30-99f9-e8996bc52aa7.png)

- Extract Features from DMP files -> Extract features from multiple MDMP files and indicate whether they are malicious or benign, can be used to create ones own set of benign and malicious features to use in the 'Create and Pre-process Pickle Dataset function'

-![image](https://user-images.githubusercontent.com/48663333/169799158-2d3f934c-22a9-4703-b5ad-4eb50a4d1923.png)

- Create and Pre-process Pickle Dataset function -> Provide a folder of benign, and a folder of malicious pkl files through which one can create dataset to train a model on

![image](https://user-images.githubusercontent.com/48663333/169799198-a26d3280-6f0a-433c-b6f8-f6d18b66cc1e.png)

- Analyse Created Dataset Feature Importance and Correlation -> Provide a dataset to have important features noted and generate images showing so

![image](https://user-images.githubusercontent.com/48663333/169799500-e9142b7c-3094-4698-a31f-5aa9ee6542be.png)
![image](https://user-images.githubusercontent.com/48663333/169799509-eb540ed1-80f0-43f3-a105-6760b0bdfd52.png)

---------------------------------------------------------
### R&D
Concerns ipynb notebooks and relevant older scripts that were used to extract data and memory dumps from the Malware Host Machine
- Cortus Collation -> separate scripts that can be used on a Linux machine for the sake of mdmp file extraction and analysis, to create a final dataset
- Cuckoo Patch -> patch that can be applied in the process.py file within the Windows Analyser Module to enable procdump usage, this also requires placement of Procmon.exe into analyser/windows/bin in cuckoo's main folder
- "Machine Learning" -> Deprecated folder that contains some old ipynb files that enable data investigation (Deprecated and mainly empty as all resulting work was added to Cortus Full Application


