import urllib.parse
from datetime import date

import boto3

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class S3Control(Evaluator):
    def __init__(self, s3Control):
        super().__init__()
        self.s3Control = s3Control
        
        self.init()
    
    def _checkAccountPublicAccessBlock(self):
        global CONFIG
        self.results['S3AccountPublicAccessBlock'] = [-1,'Off']
        try:
            stsInfo = CONFIG.get('stsInfo')
            if not stsInfo:
                print("Unable to retrieve account information")
                self.results['S3AccountPublicAccessBlock'] = [-1,'Insufficient info']
                return
        except Exception as e:
            print("Unable to retrieve account information")
            self.results['S3AccountPublicAccessBlock'] = [-1,'Insufficient info']
        try:
            resp = self.s3Control.getPublicAccessBlock({
                'AccountId': stsInfo['Account']
            })
        except Exception as e:
            print("Public access configuration not set")
            # results['S3AccountPublicAccessBlock'] = [-1,'Off']
            return
        for param in resp['PublicAccessBlockConfiguration']:
            if param != 1:
                return
        self.results['S3AccountPublicAccessBlock'] = [1,'On'] 

