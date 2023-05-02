import boto3
import re

from pprint import pprint
from .Config import Config

def _pr(s):
    pprint(s)
    
def _warn(s):
    print("[\033[1;41m__!! WARNING !!__\033[0m]" + s)
    
def aws_parseInstanceFamily(instanceFamilyInString):
    CURRENT_REGION = Config.CURRENT_REGION
    
    arr = instanceFamilyInString.split('.')
    if len(arr) > 3 or len(arr) == 1:
        return instanceFamilyInString
        
    if len(arr) == 3 and arr[0].lower() == "db":
        p = arr[1]
        s = arr[2]
    else:
        p = arr[0]
        s = arr[1]
        
    patterns = r"([a-zA-Z]+)(\d+)([a-zA-Z]*)"
    output = re.search(patterns, p)
    
    cpu = memory = 0
    
    family = p+'.'+s
    CACHE_KEYWORD = 'INSTANCE_SPEC::' + family
    spec = Config.get(CACHE_KEYWORD, [])
    if not spec:
        ec2c = boto3.client('ec2', region_name=CURRENT_REGION)
        
        resp = ec2c.describe_instance_types(InstanceTypes=[family])
        
        iType = resp.get('InstanceTypes')
        if iType:
            info = iType[0]
            cpu = info['VCpuInfo']['DefaultVCpus']
            memory = round(info['MemoryInfo']['SizeInMiB']/1024, 2)
        
        spec = {
            'vcpu' : cpu,
            'memoryInGiB' : memory
        }
        
        Config.set(CACHE_KEYWORD, spec)
    
    result = {
        "full": instanceFamilyInString,
        "prefix": p,
        "suffix": s,
        "specification": spec,
        "prefixDetail": {
            "family": output.group(1),
            "version": output.group(2),
            "attributes": output.group(3),
        }
    }

    return result
    
if __name__ == "__main__":
    Config.init()
    l = [
        "c5.2xlarge",
        "c6gn.4xlarge",
        "db.r6g.xlarge",
        "t4g.xlarge.search"
    ]
    
    for v in l:
        o = aws_parseInstanceFamily(v)
        print(o)
    