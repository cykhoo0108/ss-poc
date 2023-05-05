# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elb.html
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html

import boto3
import botocore

from services.Service import Service
from services.elb.drivers.ElbCommon import ElbCommon
from services.elb.drivers.ElbClassic import ElbClassic
from services.elb.drivers.ElbAutoScaling import ElbAutoScaling

class Elb(Service):
    def __init__ (self, region):
        super().__init__(region)
        self.elbClient = boto3.client('elbv2')
        self.elbClassicClient = boto3.client('elb')
        self.ec2Client = boto3.client('ec2')
        self.asgClient = boto3.client('autoscaling')
        
        
    def getELB(self):
        results = self.elbClient.describe_load_balancers()
        
        arr = results.get('LoadBalancers')
        while results.get('NextMarker') is not None:
            results = self.elbClient.describe_load_balancers(
                Marker = results.get('NextMarker')
            )
            arr = arr + results.get('LoadBalancers')
            
        ## TO DO: support tagging later
        
        # if self.tags is None:
        #     return arr
        
        # filteredResults = []
        # for lb in arr:
        #     tagResults = self.elbClient.describe_tags(
        #         ResourceArns = [lb['LoadBalancerArn']]
        #     )
        #     tagDesc = tagResults.get('TagDescriptions')
        #     if len(tagDesc) > 0:
        #         for desc in tagDesc:
        #             if self.resourceHasTags(desc['Tags']):
        #                 filteredResults.append(lb)
        #                 break
                    
        # return filteredResults
        
        return arr
    

    def getELBClassic(self):
        results = self.elbClassicClient.describe_load_balancers()
        
        arr = results.get('LoadBalancerDescriptions')
        while results.get('NextMarker') is not None:
            results = self.elbClient.describe_load_balancers(
                Marker = results.get('NextMarker')
            )
            
            arr = arr + results.get('LoadBalancerDescriptions')
            
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

# ASG checks
        # autoScalingGroups = self.getASGResources()
        # for asg in autoScalingGroups:
        #     print(asg)
        # $driver = 'ec2_asg';
        # foreach($asgList as $asg){
        #     if(class_exists($driver)){
        #         __info('... (ASG::Auto Scaling Group) inspecting ' . $asg['AutoScalingGroupName']);
        #         $obj = new $driver($asg, $this->asgClient, $this->elbClient, $this->elbClassicClient, $this->ec2Client);
        #         $obj->run();
        #     }
            
        #     $objs['ASG::' . $asg['AutoScalingGroupName']] = $obj->getInfo();
        #     unset($obj);
        # }
        
        
    def advise(self):
        objs = {}
        
        # ELB checks
        loadBalancers = self.getELB()
        for lb in loadBalancers:
            print(f"... (ELB::Load Balancer) inspecting {lb['LoadBalancerName']}")
            obj = ElbCommon(lb, self.elbClient)
            obj.run()
            objs[f"ELB::{lb['LoadBalancerName']}"] = obj.getInfo()
            
        # ELB classic checks
        lbClassic = self.getELBClassic()
        for lb in lbClassic:
            print(f"... (ELB::Load Balancer Classic) inspecting {lb['LoadBalancerName']}")
            obj = ElbClassic(lb, self.elbClassicClient)
            obj.run()
            objs[f"ELB Classic::{lb['LoadBalancerName']}"] = obj.getInfo()
        
        # ASG checks
        autoScalingGroups = self.getASGResources()
        for group in autoScalingGroups:
            print(f"... (ASG::Auto Scaling Group) inspecting {group['AutoScalingGroupName']}");
            obj = ElbAutoScaling(group, self.asgClient, self.elbClient, self.elbClassicClient, self.ec2Client)
            obj.run()
            objs[f"ASG::{group['AutoScalingGroupName']}"] = obj.getInfo()
            
        
        return objs
        