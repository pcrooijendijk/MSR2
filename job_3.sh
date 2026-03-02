#!/bin/bash
#SBATCH --account=cseduproject
#SBATCH --partition=csedu-prio,csedu
#SBATCH --qos=csedu-small
#SBATCH --cpus-per-task=4
#SBATCH --mem=15G
#SBATCH --gres=gpu:1
#SBATCH --time=8:00:00
#SBATCH --output=job_3.out
#SBATCH --error=job_3.err

# Navigate to the project directory
cd /vol/csedu-nobackup/project/prooijendijk/MSR2

# Commands to run your program go here, e.g.:
ID=3
python augment_mentions.py --repos-json html_lists/html_list_${ID}.json --github-token ${ID}