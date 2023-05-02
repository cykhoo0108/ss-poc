import importlib.util
import json
import os

import time
from utils.Config import Config
from services.Cloudwatch import Cloudwatch
from services.Reporter import Reporter
from services.PageBuilder import PageBuilder
import constants as _C

class Screener:
    def __init__(self):
        pass
    
    @staticmethod
    def scanByService(service, regions, filters):
        contexts = {}
        time_start = time.time()
        
        tempCount = 0
        service = service.split('::')
        
        _regions = ['GLOBAL'] if service[0] in Config.GLOBAL_SERVICES else regions

        for region in _regions:
            CURRENT_REGION = region
            cw = Cloudwatch(region)
            
            reg = region
            if region == 'GLOBAL':
                reg = regions[0]
            
            ServiceClass = Screener.getServiceModuleDynamically(service[0])    
            serv = ServiceClass(reg)
            
            ## Support --filters
            if filters != []:
                serv.setTags(filters)
                
            if len(service) > 1 and service[1] != []:
                serv.setRules(service[1])
            
            if not service[0] in contexts:
                contexts[service[0]] = {}
            
            Config.set('CWClient', cw.getClient())
                
            contexts[service[0]][region] = serv.advise()
            tempCount += len(contexts[service[0]][region])
            del serv
        
        '''
        ## <TODO>, currently S3 is using this. Need to better workaround
        if GLOBALRESOURCES:
            contexts[service[0]]['GLOBAL'] = GLOBALRESOURCES
        '''
        
        time_end = time.time()
        scanned = Config.get('scanned')
        
        with open(_C.FORK_DIR + '/' + service[0] + '.json', 'w') as f:
            json.dump(contexts[service[0]], f)
        
        with open(_C.FORK_DIR + '/' + service[0] + '.stat.json', 'w') as f:
            json.dump(scanned, f)

    @staticmethod
    def getServiceModuleDynamically(service):
        # .title() captilise the first character
        # e.g: services.iam.Iam
        
        folder = service
        if service in Config.KEYWORD_SERVICES:
            folder = service + '_'
        
        className = service.title()
        module = 'services.' + folder + '.' + className
        
        ServiceClass = getattr(importlib.import_module(module), className)
        return ServiceClass
    
    
    @staticmethod    
    def generateScreenerOutput(runmode, contexts, hasGlobal, serviceStat, regions, uploadToS3, bucket):
        stsInfo = Config.get('stsInfo')
        if runmode == 'api-raw':
            with open(_C.API_JSON, 'w') as f:
                json.dump(contexts, f)
        else:
            apiResultArray = []
            if hasGlobal:
                regions.append('GLOBAL')
            
            rawServices = []
            
            if runmode == 'report':
                params = []
                for key, val in Config.get('_SS_PARAMS').items():
                    if val != '':
                        tmp = '--' + key + ' ' + str(val)
                        params.append(tmp)
                        
                summary = Config.get('SCREENER-SUMMARY')
                ## <TODO>
                # excelObj = ExcelBuilder(stsInfo['Account'], ' '.join(params))
            
            for service, resultSets in contexts.items():
                rawServices.append(service)
                
                reporter = Reporter(service)
                reporter.process(resultSets).getSummary().getDetails()
                
                if runmode == 'report':
                    ## <TODO> -- verification
                    ## Maybe need to import module, to validate later
                    pageBuilderClass = service + 'pageBuilder'
                    if not pageBuilderClass in globals():
                        print(pageBuilderClass + ' class not found, using default pageBuilder')
                        pageBuilderClass = 'pageBuilder'
                        
                    pb = PageBuilder(service, reporter, serviceStat, regions)
                    pb.buildPage()
                    
                    ## <TODO>
                    # if service not in ['guardduty']:
                    #    excelObj.generateWorkSheet(service, reporter.cardSummary)
                else:
                    apiResultArray[service]['summary'] = reporter.getCard()
                    apiResultArray[service]['detail'] = reporter.getDetail()
            
            if runmode == 'report':
                # <TODO> 
                ## dashPB = dashboardPageBuilder('index', [], serviceStat, regions)
                ## dashPB.buildPage()
                
                # <TODO>
                ## dashPB will gather summary info, hence rearrange the sequences
                # excelObj.buildSummaryPage(summary)
                # excelObj.__save(HTML_DIR + '/')
                os.chdir(_C.ROOT_DIR)
                os.system('cd adminlte; zip -q -r output.zip html; mv output.zip ../output.zip')
                print("Pages generated, download \033[1;42moutput.zip\033[0m to view")
                print("CloudShell user, you may use this path: \033[1;42m~/service-screener/output.zip\033[0m")
                
                # <TODO>
                ## Upload to S3
                ## Not implement yet, low priority
            else:
                with open(_C.API_JSON, 'w') as f:
                    json.dump(apiResultArray, f)