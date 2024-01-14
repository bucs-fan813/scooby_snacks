# 🚀 Scooby Snacks🚀

Welcome to Scooby Snacks! Here, we have two powerful scripts that help manage resources created by Packer in an AWS account. Let's dive in and see what they do! 🏊‍♂️

## 🧹 Packer Flush Script (run.sh)

This script is your ultimate cleanup tool. It lists and removes all straggling resources created by Packer in your AWS account. Here's a quick rundown of its functions:

- **Set globals**: Sets the AWS account ID.
- **Flush VPCs**: Lists all VPCs in the AWS account.
- **Flush instances**: Lists all EC2 instances and deletes them.
- **Flush AMIs**: Lists all AMIs and de-registers them.
- **Flush snapshots**: Lists all snapshots and deletes them.
- **Flush security groups**: Lists all security groups (excluding default) and deletes them.
- **Flush key pairs**: Lists all key pairs and deletes them.

To run the script, use the following command: `./packer_flush/run.sh`

### 📝 Notes

- The script is planned to be ported to Python.
- There is a need for a dependency checker for awscli and locales-all.
- There are plans to make args for --all (default), --ec2, --snapshots, --vpcs.
- The script currently does not handle non-default VPCs.
- There is a plan to add a usage() function.

## 💰 Packer Cost Estimation Script (run.sh)

This script is your personal finance advisor. It estimates the monthly cost for resources created by Packer, comparing the Standard tier vs Archive tier for snapshots. Here's what it does:

1. **Set globals**: Sets the global variables for the script.
2. **Check ACCOUNT_ID**: Checks if the ACCOUNT_ID is valid.
3. **Get snapshots**: Retrieves snapshots created by Packer.
4. **Check snapshots array**: Checks if the snapshots array is empty.
5. **Get snapshot size**: Retrieves the size of each snapshot and sums up the results.
6. **Calculate costs**: Calculates the monthly and annual costs for snapshots.
7. **Print report**: Prints a report of the total size of snapshots, costs, and savings.

To run the script, use the following command: `./packer_totals/run.sh`

### 📝 Notes

- The script requires the locales-all package to be installed.
- The ACCOUNT_ID must be a 12 digit AWS account ID or "self" (default).
- There are several TODOs in the script, including porting the script to Python, adding a dependency checker for awscli and locales-all, handling snapshot_total_size as bytes shown in GB, TB and/or PB, adjusting to only calculate X of Y snapshots to convert to archive tier, adding usage() function, and adding extra reporting for # of snapshots, # of AMIs, all snapshots (using flexible-snapshot-proxy).

That's all, folks! We hope you find these scripts useful. Happy coding! 🎉