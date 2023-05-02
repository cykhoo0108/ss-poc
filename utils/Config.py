import traceback
import os
import boto3

class Config:
    # DIR_ROOT = os.getcwd()
    # DIR_SERVICE = DIR_ROOT + '/services'
    # DIR_TEMPLATE = DIR_ROOT + '/templates'
    # DIR_HTML = DIR_ROOT + '/adminlte/html'
    # DIR_FORK = DIR_ROOT + '/__fork'
    
    # SESSUID_FILENAME = 'sess-uuid'
    
    # PATH_GENERAL_CONF = DIR_SERVICE + '/general.reporter.json'
    
    AWS_SDK = {
        'RDSCLIENT_VERS': '2014-10-31',
        'EC2CLIENT_VERS': '2016-11-15',
        'COMPOPTCLIENT_VERS': '2019-11-01',
        'COSTEXPLORERCLIENT_VERS': '2017-10-25',
        'ELBCLIENT_VERS': '2015-12-01',
        'ELBCLASSICCLIENT_VERS': '2012-06-01',
        'ASGCLIENT_VERS': '2011-01-01',
        'IAMCLIENT_VERS': '2010-05-08',
        'S3CLIENT_VERS': '2006-03-01',
        'S3CONTROL_VERS': '2018-08-20',
        'STSCLIENT_VERS': '2011-06-15',
        'CLOUDWATCHCLIENT_VERS': '2010-08-01',
        'SSMCLIENT_VERS': '2014-11-06',
        'AOSCLIENT_VERS': '2021-01-01',
        'EFSCLIENT_VERS': '2015-02-01',
        'GUARDDUTYCLIENT_VERS': '2017-11-28',
        'LAMBDACLIENT_VERS': '2015-03-31',
        'ACCOUNTCLIENT_VERS': '2021-02-01',
        'signature_version': 'v4'
    }

    ADVISOR = {
        'TITLE': 'Service Screener',
        'VERSION': '2.0.0',
        'LAST_UPDATE': '1-May-2023'
    }

    ADMINLTE = {
        'VERSION': '3.1.0',
        'DATERANGE': '2014-2021',
        'URL': 'https://adminlte.io',
        'TITLE': 'AdminLTE.io'
    }

    GLOBAL_SERVICES = [
        'iam'
    ]
    
    KEYWORD_SERVICES = [
        'lambda'    
    ]
    
    CURRENT_REGION = 'us-east-1'
    
    @staticmethod
    def init():
        global cache
        cache = {}
    
    @staticmethod
    def setAccountInfo(__AWS_CONFIG):
        print(" -- Acquiring identify info...")
        stsClient = boto3.client('sts')
        
        resp = stsClient.get_caller_identity()
        stsInfo = {
            'UserId': resp.get('UserId'),
            'Account': resp.get('Account'),
            'Arn': resp.get('Arn')
        }

        Config.set('stsInfo', stsInfo)
        
       
    @staticmethod 
    def set(key, val):
        cache[key] = val

    @staticmethod
    def get(key, defaultValue = False):
        ## <TODO>, fix the DEBUG variable
        DEBUG = False
        if key in cache:
            return cache[key]
        
        if defaultValue == False:
            if DEBUG:
                traceback.print_exc()
        
        return defaultValue

try:
    if configHasInit:
        pass
except NameError:
    dashboard = {}
    Config.init()
    configHasInit = True

if __name__ == "__main__":
    print(os.getcwd())