import time
import os
import json
import locale
from multiprocessing import Pool

from utils.Config import Config
from utils.ArguParser import ArguParser
import constants as _C
from Screener import Screener

def number_format(num, places=2):
    return locale.format_string("%.*f", (places, num), True)

_cli_options = ArguParser.Load()

debugFlag = _cli_options['debug']
# feedbackFlag = _cli_options['feedback']
testmode = _cli_options['test']
bucket = _cli_options['bucket']
runmode = _cli_options['mode']
filters = _cli_options['filters']

DEBUG = True if debugFlag in _C.CLI_TRUE_KEYWORD_ARRAY or debugFlag is True else False
# feedbackFlag = True if feedbackFlag in _C.CLI_TRUE_KEYWORD_ARRAY or feedbackFlag is True else False
testmode = True if testmode in _C.CLI_TRUE_KEYWORD_ARRAY or testmode is True else False

runmode = runmode if runmode in ['api-raw', 'api-full', 'report'] else 'report'

# <TODO>, yet to convert to python
# S3 upload specific variables 
# uploadToS3 = Uploader.getConfirmationToUploadToS3(bucket)

# <TODO> analyse the impact profile switching
profile = _cli_options['profile']
if profile:
    global PHPSDK_CRED_PROFILE
    PHPSDK_CRED_PROFILE = profile

_AWS_OPTIONS = {
    'signature_version': Config.AWS_SDK['signature_version']
}

Config.init()
Config.set('_AWS_OPTIONS', _AWS_OPTIONS)
Config.set('scanned', {'resources': 0, 'rules': 0, 'exceptions': 0})

_AWS_OPTIONS = {
    'signature_version': Config.AWS_SDK['signature_version']
}

Config.set("_SS_PARAMS", _cli_options)
Config.set("_AWS_OPTIONS", _AWS_OPTIONS)

regions = _cli_options['region'].split(',')
services = _cli_options['services'].split(',')

tempConfig = _AWS_OPTIONS.copy();
tempConfig['region'] = regions[0]
Config.setAccountInfo(tempConfig)

contexts = {}
serviceStat = {}
GLOBALRESOURCES = []

oo = Config.get('_AWS_OPTIONS')

overallTimeStart = time.time()
os.chdir('__fork')
os.system('rm -f *.json; echo > tail.txt')

input_ranges = []
for service in services:
    input_ranges = [(service, regions, filters) for service in services]

pool = Pool(processes=len(services))
pool.starmap(Screener.scanByService, input_ranges)

## <TODO>
## parallel logic to be implement in Python
scanned = {
    'resources': 0,
    'rules': 0,
    'exceptions': 0
}

hasGlobal = False
for file in os.listdir(_C.FORK_DIR):
    if file[0] == '.' or file == _C.SESSUID_FILENAME or file == 'tail.txt' or file == 'error.txt':
        continue
    f = file.split('.')
    if len(f) == 2:
        contexts[f[0]] = json.loads(open(_C.FORK_DIR + '/' + file).read())
    else:
        cnt, rules, exceptions = list(json.loads(open(_C.FORK_DIR + '/' + file).read()).values())
        serviceStat[f[0]] = cnt
        scanned['resources'] += cnt
        scanned['rules'] += rules
        scanned['exceptions'] += exceptions
        if f[0] in Config.GLOBAL_SERVICES:
            hasGlobal = True

if testmode:
    exit("Test mode enable, script halted")

timespent = round(time.time() - overallTimeStart, 3)
scanned['timespent'] = timespent
Config.set('SCREENER-SUMMARY', scanned)

print("Total Resources scanned: " + str(number_format(scanned['resources'])) + " | No. Rules executed: " + str(number_format(scanned['rules'])))
print("Time consumed (seconds): " + str(timespent))

# Cleanup
os.chdir(_C.HTML_DIR)
os.system('rm -f *.html; rm -f error.txt')

if os.path.exists(_C.FORK_DIR + '/error.txt'):
    os.chdir(_C.FORK_DIR)
    os.system('mv error.txt ' + _C.HTML_DIR + '/error.txt')

os.chdir(_C.FORK_DIR)
# os.system('rm -f *.json')

os.chdir(_C.ROOT_DIR)
os.system('rm -f output.zip')

## Generate output
uploadToS3 = False

## <TODO>
## Might be able breakdown the function further to leverage on multi-processing
Screener.generateScreenerOutput(runmode, contexts, hasGlobal, serviceStat, regions, uploadToS3, bucket)

os.chdir(_C.FORK_DIR)
os.system('rm -f tail.txt')

print("@ Thank you for using " + Config.ADVISOR['TITLE'] + " @")