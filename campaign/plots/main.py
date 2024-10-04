'''
This serves as the entry point for the plotting module for campaign debug data.
'''
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
import sys


if __name__ == '__main__':
    # Read input file that was passed as argument
    # in_file = sys.argv[1]
    
    # For now hardcode the input file
    in_file = "/home/cosmix/thesis/LibAFL/campaign/plots/hitcount_maps/libpng_first_campaign_24.txt"
    
    # Read from ./hitcount_maps/<in_file> into a pandas dataframe
    df = pd.read_csv(in_file, header=None, delimiter=':', names=['range', 'hit_count'])
    
    # Get bins for the histogram
    max_hit_count = df['hit_count'].max()
    max_power = len(str(max_hit_count))
    
    # Create bins with logspace, from 0 to max_power
    bins = np.logspace(0, max_power, num=max_power+1)
    
    # Plot the histogram
    counts, bin_edges, patches = plt.hist(df['hit_count'], bins=bins, color='blue', edgecolor='black')
    plt.xscale('log')
    
    # Set the title and labels
    plt.title(os.path.basename(in_file))
    plt.xlabel('Hit Count Range')
    plt.ylabel('Number of Hit Counts')
    
    # Set the tick location to match the bins
    tick_labels = [f"$10^{int(np.log10(b))}$" for b in bins]
    plt.xticks(bins, tick_labels, rotation=45)
    
    # Annotate each bin with the number of hit counts, placed above the bar
    for count, bin_start, bin_end in zip(counts, bin_edges[:-1], bin_edges[1:]):
        bin_center = (bin_start + bin_end) / 2
        # shift bin_center to the left for better visibility
        bin_center = bin_center * 0.75
        plt.text(bin_center, count, f'{int(count)}', ha='center', va='bottom')
    
    # Save the plot
    out_file = "/home/cosmix/thesis/LibAFL/campaign/plots/output/" + os.path.basename(in_file) + ".png"
    plt.tight_layout()
    plt.savefig(out_file)
    
