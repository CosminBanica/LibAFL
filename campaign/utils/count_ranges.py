'''
This is a tool for counting the number of address ranges in a given resulting filter file.
'''
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os


def plot_count_evolution(counts, out_file):
    '''
    Takes as input list of counts and plots the count evolution. Save the plot as png file.
    Plot should be a line plot with x-axis as the index of the counts and y-axis as the counts.
    '''
    plt.plot(counts)
    plt.xlabel('Index')
    plt.ylabel('Number of Address Ranges')
    plt.title('Count Evolution')
    plt.savefig(out_file)
    plt.clf()


def get_ranges_count(file_path):
    '''
    Returns the number of address ranges in the given file, as a list, one count per line.
    '''
    counts = []
    with open(file_path, 'r') as f:
        for line in f:
            ranges = []
            line = line.strip()
            if line:
                ranges.extend(line.split())
            counts.append(len(ranges))
                
    return counts


if __name__ == '__main__':
    # Directory where the logs are stored
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/../plots/logs/"
    
    # Get list of directories that start with ad in the directory
    dirs = os.listdir(dir_path)
    if "archived" in dirs:
        dirs.remove("archived")
        
    input_files = []
        
    for dir in dirs:
        # Get the resulting_filter_<id>.txt file in the directory
        if not dir.startswith("ad"):
            continue
        
        log_files = os.listdir(dir_path + dir)
        for file in log_files:
            if file.startswith("resulting_filter"):
                input_files.append(dir_path + dir + "/" + file)
                break
    
    current_dir = os.path.dirname(os.path.realpath(__file__))
    output = []
    for file in input_files:
        counts = get_ranges_count(file)
        png_path = current_dir + "/" + os.path.basename(file) + ".png"
        plot_count_evolution(counts, png_path)
        output.append(f"{file}: {counts}")
    
    # Write the output to a file
    
    out_file = current_dir + "/ranges_count.txt"
    with open(out_file, 'w') as f:
        f.write('\n'.join(output))
    
    
    