#!/usr/bin/python3
# -*- coding: utf-8 -*-

# CAFIR Forensics Automation
# Created by Matt Coons | @arborbytes

#References: https://medium.com/google-cloud/using-gcloud-and-python-client-library-with-google-compute-engine-eaf1b19d8099

#-#-#-#-#-#-#Imports#-#-#-#-#-#-#
import subprocess
import json
import shlex
import sys
import argparse
import time
import subprocess

#-#-#-#-#-#-#User Configurable Options#-#-#-#-#-#-#
parser = argparse.ArgumentParser(description='Cloud Automated Forensics and Incident Response (CAFIR) -- For this tool to work, you need the GCloud SDK: https://cloud.google.com/sdk')
parser.add_argument('-d', action="store_true", default=False, dest="d", help="Discovery Mode")
parser.add_argument('-c', action="store_true", default=False, dest="c", help="Containment Mode, requires a Target Project (-s), Network Tag (-t)")
parser.add_argument('-t', action="store", default=False, dest="t", type=str, help="Network Tag, used for Containment mode")
parser.add_argument('-f', action="store_true", default=False, dest="f", help="Forensics Mode, requires a Target VM (-v), Analysis VM, Target Project (-s), Analysis Project (-p)")
parser.add_argument('-v', action="store", default=False, dest="v", type=str, help="Target Disk Name, used with Forensics Mode")
parser.add_argument('-s', action="store", default=False, dest="s", type=str, help="Target Project")
parser.add_argument('-p', action="store", default=False, dest="p", type=str, help="Analysis (Forensics) Project")
parser.add_argument('-a', action="store", default=False, dest="a", type=str, help="Analysis (Forensics) VM")

all_args = parser.parse_args()
discovery_mode = all_args.d
containment_mode = all_args.c
forensics_mode = all_args.f
target_disk = all_args.v
target_project = all_args.s
analysis_project = all_args.p
analysis_vm = all_args.a
network_tags = all_args.t

#-#-#-#-#-#-#Print CAFIR Logo#-#-#-#-#-#-#

caf_logo = """
╔═╗╔═╗╔═╗╦╦═╗
║  ╠═╣╠╣ ║╠╦╝
╚═╝╩ ╩╚  ╩╩╚═
"""

print(caf_logo)

#-#-#-#-#-#-#Discovery Mode#-#-#-#-#-#-#
if discovery_mode == True:
    project_list_command = "gcloud projects list --format json"
    project_output = subprocess.check_output(shlex.split(project_list_command))
    project_output_json = json.loads(project_output)

    for project_disc in project_output_json: 
        project_id = project_disc["projectId"]
        instance_list_command = "gcloud compute instances list --format json --project "+ project_id
        instance_output_json = json.loads(subprocess.check_output(shlex.split(instance_list_command)))

        print ("\n=========================")
        print("Discovering VMs in Project: \nProject Name: " + project_disc["name"] + "\nProject Create Date: " + project_disc["createTime"] + "\nProject ID: " + project_disc["projectId"])
        print ("\n=========================")

        if instance_output_json == []:
            print("No VMs in this project")
        else:
            for vm in instance_output_json:
                print("VM name: " + vm["name"])
                print("- VM create timestamp: " + vm["creationTimestamp"])
                try:
                    print("- VM labels: " + str(vm["labels"]))
                except:
                    pass
                for disk in vm["disks"]:
                    print("- Disk Name: " + disk["deviceName"])
                    print("  - Disk Boot Device: " + str(disk["boot"]))
                    print("  - Disk Size: " + disk["diskSizeGb"] + "GB")
                for ip in vm["networkInterfaces"]:
                    print("- VM network IP: " + ip["networkIP"])
                    for externalip in ip["accessConfigs"]: 
                        try:
                            print("- External IP: " + externalip["natIP"])
                        except:
                            pass
                print ("- VM status: " + vm["status"])
                print ("- VM Zone: " + vm["zone"])
                try:
                    print("- Network Tags: " + str(vm["tags"]["items"]))
                except:
                    pass
                print ("-------------------------")
    sys.exit()

#-#-#-#-#-#-#Containment Mode#-#-#-#-#-#-#

# For each project id in the list, get the instance details
if containment_mode == True:
    containment_fw_inbound = "gcloud compute --project=" + target_project + " firewall-rules create quarantine-in --direction=INGRESS --priority=0 --network=default --action=DENY --rules=all --target-tags=" + network_tags
    containment_fw_outbound = "gcloud compute --project=" + target_project + " firewall-rules create quarantine-out --direction=EGRESS --priority=0 --network=default --action=DENY --rules=all --target-tags=" + network_tags

    answer = input("\n Are you sure you wish to contain hosts with network tags of: " + network_tags + "? \n Enter y to continue, n to exit\n").lower().strip()
    if answer == "y":
        pass
    elif answer == "n":
        sys.exit("You chose not to continue, goodbye!")

    inbound_network_contain = subprocess.check_output(shlex.split(containment_fw_inbound))
    outbound_network_contain = subprocess.check_output(shlex.split(containment_fw_outbound))

    print("\nInbound and Outbound Quarantine Firewall Rules created. Both Firewall rules have logging Enabled.\nThe newly created Firewall rules will have names quarantine-in and quarantine-out\n")
    sys.exit("Goodbye!")

#-#-#-#-#-#-#Forensics Mode#-#-#-#-#-#-#
if forensics_mode == True:

    # Enumerate target disk 
    forensics_target_disc = "gcloud compute disks list --project=" + target_project +  " --filter=NAME=" + target_disk + " --format=json"
    forensics_target_disc_json = json.loads(subprocess.check_output(shlex.split(forensics_target_disc)))
    
    for drive in forensics_target_disc_json:
        target_size = drive["sizeGb"]
        target_zone = drive["zone"].rsplit("/", 1)[1]
        target_type = drive["type"].rsplit("/", 1)[1]

    # Enumerate forensics VM 
    forensics_analysisvm_disc = "gcloud compute instances list --project=" + target_project +  " --filter=NAME=" + analysis_vm + " --format=json"
    forensics_analysisvm_disc_json = json.loads(subprocess.check_output(shlex.split(forensics_analysisvm_disc)))
    
    for analystvm in forensics_analysisvm_disc_json:
        analystvm_zone = analystvm["zone"].rsplit("/", 1)[1]
   
    # Take a snapshot of the target system
    forensics_snapshot = "gcloud compute disks snapshot " + target_disk + " --project=" + target_project + " --snapshot-names=" + target_disk + "-snapshot --zone=" + target_zone
    forensics_snapshot_exe = subprocess.check_output(shlex.split(forensics_snapshot))

    # Set snapshot & forensic disk naming convention
    snapshot_name = target_disk + "-snapshot"
    forensic_disk_name = target_disk + "-forensics"

    # Create a disk from the created snapshot
    forensics_snapshot_todisk = "gcloud compute disks create " + forensic_disk_name + " --project=" + analysis_project + " --type=" + target_type + " --size=" + target_size + " --zone=" + analystvm_zone + " --source-snapshot=" + snapshot_name
    forensics_snapshot_todisk_exe = subprocess.check_output(shlex.split(forensics_snapshot_todisk))

    # Attach the new disk to the analyst VM
    forensic_mount_disk = "gcloud compute instances attach-disk " + analysis_vm + " --disk=" + forensic_disk_name + " --zone=" + analystvm_zone + " --mode=ro"
    forensic_mount_disk_exe = subprocess.check_output(shlex.split(forensic_mount_disk))

else: 
    print("\n\nPlease specify a mode, or for help, run CAFIR with the -h flag\n\n")
    sys.exit()
