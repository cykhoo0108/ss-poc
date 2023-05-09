import urllib.parse
from datetime import date

import boto3
import json

from utils.Config import Config
from utils.Policy import Policy
from services.Evaluator import Evaluator

class S3Bucket(Evaluator):
    def __init__(self, bucket, s3Client):
        super().__init__()
        self.bucket = bucket
        self.s3Client = s3Client
        
        self.init()

    def _checkEncrypted(self):
        self.results['ServerSideEncrypted'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_encryption(
                Bucket=self.bucket
            )
            print(resp)
        except self.s3Client.exceptions as e:
            print(e)
            if e.getAwsErrorCode() == 'ServerSideEncryptionConfigurationNotFoundError':
                self.results['ServerSideEncrypted'] = [-1, 'Off']

    def _checkPublicAcessBlock(self):
        self.results['PublicAccessBlock'] = [-1, 'Off']
        try:
            resp = self.s3Client.get_public_access_block(
                Bucket=self.bucket
            )
            for param in resp['PublicAccessBlockConfiguration']:
                if param != 1:
                    return
        except self.s3Client.exceptions as e:
            if e.getAwsErrorCode() == 'NoSuchPublicAccessBlockConfiguration':
                return
        self.results['PublicAccessBlock'] = [1, 'On']
    
    def _checkMfaDelete(self):
        self.results['MFADelete'] = [-1, 'Off']
        resp = self.s3Client.get_bucket_versioning(
            Bucket=self.bucket
        )
        if resp.get('Status') == "MFADelete":
            self.results['MFADelete'] = [1, 'On']

    def _checkVersioning(self):
        self.results['BucketVersioning'] = [-1, 'Off']
        resp = self.s3Client.get_bucket_versioning(
            Bucket=self.bucket
        )
        if resp.get('Status') == "Enabled":
            self.results['BucketVersioning'] = [1, 'On']

    def _checkObjectLock(self):
        self.results['ObjectLock'] = [1, 'On']
        try:
            resp = self.s3Client.get_object_lock_configuration(
                Bucket=self.bucket
            )
        except self.s3Client.exceptions as e:
            if e.get_aws_error_code() == 'ObjectLockConfigurationNotFoundError':
                self.results['ObjectLock'] = [-1, 'Off']

    def _checkBucketReplication(self):
        self.results['BucketReplication'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_replication(
                Bucket=self.bucket
            )
        except self.s3Client.exceptions as e:
            if e.get_aws_error_code() == 'ReplicationConfigurationNotFoundError':
                self.results['BucketReplication'] = [-1, 'Off']

    def _checkLifecycle(self):
        self.results['BucketLifecycle'] = [1, 'On']
        try:
            resp = self.s3Client.get_bucket_lifecycle(
                Bucket=self.bucket
            )
        except self.s3Client.exceptions as e:
            if e.get_aws_error_code() == 'NoSuchLifecycleConfiguration':
                self.results['BucketLifecycle'] = [-1, 'Off']

    def _checkLogging(self):
        self.results['BucketLogging'] = [1, 'On']
        resp = self.s3Client.get_bucket_logging(
            Bucket=self.bucket
        )
        ele = resp.get('LoggingEnabled')
        if not ele:
            self.results['BucketLogging'] = [-1, 'Off']
    
    def _checkIntelligentTiering(self): 
        self.results['ObjectsInIntelligentTier'] = [1,'On'] 
        resp = self.s3Client.list_objects(
            Bucket = self.bucket,
            MaxKeys = 1000
        )
        if not resp.get('Contents'):
            return
        for object in resp.get('Contents'):
            if object['StorageClass'] != "INTELLIGENTTIERING":
                self.results['ObjectsInIntelligentTier'] = [-1,'Off']
                return 
            
    def _checkTls(self):
        self.results['TlsEnforced'] = [-1, 'Off']
        try:
            resp = self.s3Client.get_bucket_policy(
                Bucket=self.bucket
            )
            policy = json.loads(resp.get('Policy'))
            for obj in policy['Statement']: 
                if 'Condition' not in obj:
                    continue

                cc = json.loads(json.dumps(obj['Condition']))

                if obj['Effect'] == "Deny":
                    for cond in cc:
                        if 'aws:SecureTransport' in cond and cond['aws:SecureTransport'] == "false":
                            self.results['TlsEnforced'] = [1, 'On']
                            return

                if obj['Effect'] == "Allow":
                    for cond in cc:
                        if 'aws:SecureTransport' in cond and cond['aws:SecureTransport'] == "true":
                            self.results['TlsEnforced'] = [1, 'On']
                            return
        except self.s3Client.exceptions as e:
            return

