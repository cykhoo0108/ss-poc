# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html

import boto3
import botocore

import json
import time

from utils.Config import Config
from services.Service import Service
from services.ec2.drivers.Ec2Instance import Ec2Instance
from services.ec2.drivers.Ec2CompOpt import Ec2CompOpt
from services.ec2.drivers.Ec2EbsVolume import Ec2EbsVolume
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup
from services.ec2.drivers.Ec2CostExplorerRecs import Ec2CostExplorerRecs

class Ec2(Service):
    def __init__(self, region):
        super().__init__(region)
        self.ec2Client = boto3.client('ec2')
        self.ssmClient = boto3.client('ssm')
        self.compOptClient = boto3.client('compute-optimizer')
        self.ceClient = boto3.client('ce')
        self.asgClient = boto3.client('autoscaling')
    
    # get EC2 Instance resources
    def getResources(self):
        filters = []
        if self.tags:
            filters = self.tags
                
        results = self.ec2Client.describe_instances(
            Filters = filters
        )
        
            
        arr = results.get('Reservations')
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_instances(
                Filters = filters,
                NextToken = results.get('NextToken')
            )    
            arr = arr + results.get('Reservations')

        return arr
    
    # get EC2 Security Group resources
    def getEC2SecurityGroups(self,instance):
        if 'SecurityGroups' not in instance:
            print(f"Security Group not found in {instance['InstanceId']}")
            return {}
        
        arr = []    
        filters = []
        groupIds = []
        if self.tags:
            filters = self.tags
        
        for group in instance['SecurityGroups']:
            groupIds.append(group['GroupId'])
        
        results = self.ec2Client.describe_security_groups(
            GroupIds=groupIds,
            Filters=filters
        )
        arr = results.get('SecurityGroups')
        
        while results.get('NextToken') is not None:
            results = self.ec2Client.describeSecurityGroups(
                GroupIds = groupIds,
                Filters=filters,
                NextToken = results.get('NextToken')
                )
            arr = arr + results.get('SecurityGroups')
        
        return arr
    
    def getEBSResources(self):
        filters = []
        
        if self.tags:
            filters = self.tags
        
        results = self.ec2Client.describe_volumes(
            Filters = filters
        )
        
        arr = results.get('Volumes')
        while results.get('NextToken') is not None:
            results = self.ec2Client.describe_volumes(
                Filters = filters,
                NextToken = results.get('NextToken')
            )    
            arr = arr + results.get('Reservations')

        return arr
        
    def getASGResources(self):
        filters = []
        if self.tags:
            filters = self.tags
        
        results = self.asgClient.describe_auto_scaling_groups(
            Filters = filters
        )
        arr = results.get('AutoScalingGroups')
        while results.get('NextToken') is not None:
            results = self.asgClient.describe_auto_scaling_groups(
                Filters = filters,
                NextToken = results.get('NextToken')
            )
            
            arr = arr + results.get('AutoScalingGroups')
        
        return arr
    
    def advise(self):
        objs = {}
        secGroups = {}
        
        # compute optimizer checks
        try:
            compOptPath = "/aws/service/global-infrastructure/regions/" + self._AWS_OPTIONS['region'] + "/services/compute-optimizer";
            compOptCheck = self.ssmClient.get_parameters_by_path(
                Path = compOptPath    
            )
            
            if 'Parameters' in compOptCheck and len(compOptCheck['Parameters']) > 0:
                print('... (Compute Optimizer Recommendations) inspecting')
                obj = Ec2CompOpt(self.compOptClient)
                obj.run()
                
        except Exception as e:
            print(e)
            print("!!! Skipping compute optimizer check for <" + self._AWS_OPTIONS['region'] + ">")
            
        
        #EC2 Cost Explorer checks
        print('... (Cost Explorer Recommendations) inspecting')
        obj = Ec2CostExplorerRecs(self.ceClient)
        obj.run()

        objs['CostExplorer'] = obj.getInfo()
        
        
        # EC2 instance checks
        instances = self.getResources()
        for instance in instances:
            instanceData = instance['Instances'][0]
            print('... (EC2) inspecting ' + instanceData['InstanceId'])
            obj = Ec2Instance(instanceData,self.ec2Client)
            obj.run()
            
            objs[f"EC2::{instanceData['InstanceId']}"] = obj.getInfo()
            
            ## Gather SecGroups in dict first to prevent check same sec groups multiple time
            instanceSG = self.getEC2SecurityGroups(instanceData)
            for group in instanceSG:
                secGroups[group['GroupId']] = group
            
        
        #EBS checks
        volumes = self.getEBSResources()
        for volume in volumes:
            print('... (EBS) inspecting ' + volume['VolumeId'])
            obj = Ec2EbsVolume(volume,self.ec2Client)
            obj.run()
            objs[f"EBS::{volume['VolumeId']}"] = obj.getInfo()
            
            
        # SG checks
        for group in secGroups.values():
            print(f"... (EC2::Security Group) inspecting {group['GroupId']}")
            obj = Ec2SecGroup(group, self.ec2Client)
            obj.run()
            
            objs[f"SG::{group['GroupId']}"] = obj.getInfo()
        
        return objs