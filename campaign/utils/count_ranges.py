'''
This is a tool for counting the number of address ranges in a given file.
'''

if __name__ == '__main__':
    in_file = "/home/cosmix/thesis/LibAFL/campaign/utils/resulting_filter2.txt"
    
    ranges = []
    
    # Read all lines from file until EOF
    # each line will either be empty, or will contain a list of address ranges
    # example line: 7f7b05751652-7f7b0575165f 7f7b057515ae-7f7b057515c0 7f7b0530488d-7f7b05304895 7f7b05304895-7f7b05304896 7f7b05304870-7f7b0530488d
    
    with open(in_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                ranges.extend(line.split())
                
    print(f"Number of address ranges: {len(ranges)}")