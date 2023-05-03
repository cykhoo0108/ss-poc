import boto3
import botocore

import json
import time


from utils.Config import Config
from utils.Tools import _pr
from services.Service import Service
from botocore.config import Config as bConfig

# import drivers here
from services.s3.drivers.S3Bucket import S3Bucket
from services.s3.drivers.S3Control import S3Control

class S3(Service):
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        conf = bConfig(region_name=region)
        self.s3Client = boto3.client('s3')
        self.s3Control = boto3.client('s3control')
        
        # buckets = Config.get('s3::buckets', [])
    
    def getResources(self):
        buckets = Config.get('s3::buckets', {})
        if not buckets:
            buckets = {}
            results = self.s3Client.list_buckets()
            
            arr = results.get('Buckets')
            while results.get('Maker') is not None:
                results = self.s3Client.list_buckets(
                    Maker = results.get('Maker')
                )    
                arr = arr + results.get('Buckets')
            
            for ind, bucket in enumerate(arr):
                loc = self.s3Client.get_bucket_location(
                    Bucket = bucket['Name']
                )
                reg = loc.get('LocationConstraint')
                if not reg in buckets:
                    buckets[reg] = []
                buckets[reg].append(arr[ind])
            
            Config.set('s3::buckets', buckets)
        
        if self.region in buckets:
            _buckets = buckets[self.region]
        else:
            return []
            
        if not self.tags:
            return _buckets
        
        filteredBuckets = []
        for bucket in _buckets:
            try:
                result = self.s3Client.get_bucket_tagging(Bucket = bucket['Name'])
                tags =result.get('TagSet')
            
                if self.resourceHasTags(tags):
                    filteredBuckets.append(bucket)
            except S3E as e:
                ## Do nothing, no tags has been define;clear
                pass
            
        return filteredBuckets    
    
    def advise(self):
        global GLOBALRESOURCES
        objs = []
        driver = 's3_control'
        if driver in globals():
            print('... (S3Account) inspecting ')
            obj = globals()[driver](self.s3Control)
            obj.run()
            
            objs["Account::Bucket"] = obj.getInfo()
            Config.set('GLOBALRESOURCES', objs)
            
            objs = []
            del obj
            
        buckets = self.getResources()
        for bucket in buckets:
            print('... (S3Bucket) inspecting ' + bucket['Name'])
            driver = 's3_s3'
            if driver in globals():
                obj = globals()[driver](bucket['Name'], self.s3Client)
                obj.run()
                
                objs[bucket['Name']] = obj.getInfo()
                del obj
                
        return objs

        
if __name__ == "__main__":
    Config.init()
    o = S3('ap-southeast-1')
    o.advise()