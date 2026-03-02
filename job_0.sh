#!/bin/bash
#SBATCH --job-name=gh-augment
#SBATCH --account=cseduproject
#SBATCH --partition=cnczshort
#SBATCH --qos=csedu-nor+
#SBATCH --time=11:00:00
#SBATCH --cpus-per-task=1
#SBATCH --array=0-10
#SBATCH --output=logs/job_%A_%a.out
#SBATCH --error=logs/job_%A_%a.err

# Navigate to the project directory
cd /vol/csedu-nobackup/project/prooijendijk/MSR2

# Commands to run your program go here, e.g.:
ID=0
python augment_mentions.py --repos-json html_lists/html_list_${ID}.json --github-token ${ID}