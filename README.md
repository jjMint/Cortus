# Cortus - Process Memory Analysis and Detection
Repository for Process Memory Analysis (Cortus) toolset
-------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------
## Introduction
---------------------------------------------------------
This repository concerns the install of Cuckoo and Radare2 along with the scripts used to generate process memory datasets and extract features from said process memory.

It also contains the code used to create a machine learning model of the extracted features as a proof of concept of the value derived from only process memory.

---------------------------------------------------------
## Platform and Environment
---------------------------------------------------------
Concerns the Cuckoo and Radare installation scripts along with batch scripts that perform the following:
- Benign process startup and activity generation
- Process memory dumping and collection
- Process memory collection from malicious process using cuckoo
- Environment set-up and vm sourcing for cuckoo

---------------------------------------------------------
## RadarScraper
---------------------------------------------------------
Concerns feature extraction and storage from the process memory datasets
