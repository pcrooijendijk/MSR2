#!/bin/bash
#SBATCH --account=cseduproject
#SBATCH --partition=cnczshort
#SBATCH --qos=csedu-nor+
#SBATCH --ntasks=10
#SBATCH --cpus-per-task=1
#SBATCH --time=11:00:00
#SBATCH --output=job_0.out
#SBATCH --error=job_0.err

# Navigate to the project directory
cd /vol/csedu-nobackup/project/prooijendijk/MSR2

# Commands to run your program go here, e.g.:
ID=0
python augment_mentions.py --repos-json html_lists/html_list_${ID}.json --github-token ${ID}