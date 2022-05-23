# Cortus - Process Memory Analysis and Detection
Repository for Process Memory Analysis (Cortus) toolset
-------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------
## Introduction
---------------------------------------------------------
This repository concerns the install of Cuckoo and Radare2 along with the scripts used to generate process memory datasets and extract features from said process memory.

It also contains the code used to create a machine learning model of the extracted features as a proof of concept of the value derived from only process memory.


---------------------------------------------------------
## Requirements
---------------------------------------------------------


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
# R&D
Concerns ipynb notebooks and relevant older scripts that were used to extract data and memory dumps from the Malware Host Machine
- Cortus Collation -> separate scripts that can be used on a Linux machine for the sake of mdmp file extraction and analysis, to create a final dataset
- Cuckoo Patch -> patch that can be applied in the process.py file within the Windows Analyser Module to enable procdump usage, this also requires placement of Procmon.exe into analyser/windows/bin in cuckoo's main folder
- "Machine Learning" -> Deprecated folder that contains some old ipynb files that enable data investigation (Deprecated and mainly empty as all resulting work was added to Cortus Full Application


