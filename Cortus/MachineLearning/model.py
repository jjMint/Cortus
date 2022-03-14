# ------------------------------------------------------------------------------------------------------------------
# Introduction
# ------------------------------------------------------------------------------------------------------------------
# Author: Joshua Keegan
# Process Memory unsupervised learning model to help determine points of interest
# ------------------------------------------------------------------------------------------------------------------




def main(argv) :
    parser = argparse.ArgumentParser(description='Create a complete dataset based on input files')
    parser.add_argument('--iFolder', dest='inputFolder', help='The input folder for benign process dumps')

    args = parser.parse_args()

if __name__ == "__main__":
    main(sys.argv[1:])
