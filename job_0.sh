#!/bin/bash
#SBATCH --job-name=gh-augment
#SBATCH --account=cseduproject
#SBATCH --partition=csedu-prio,csedu
#SBATCH --qos=csedu-large
#SBATCH --time=11:00:00
#SBATCH --cpus-per-task=1
#SBATCH --output=job_0.out
#SBATCH --error=job_0.err

# Navigate to the project directory
cd /vol/csedu-nobackup/project/prooijendijk/MSR2

# Commands to run your program go here, e.g.:
ID=0
python augment_mentions.py --repos-json html_lists/html_list_${ID}.json --github-token ${ID} --out-csv augmented_mentions_${ID}.csv