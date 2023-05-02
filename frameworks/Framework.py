import os
import json

import constants as _C

class Framework():
    def __init__(self, data):
        self.data = data
        self.framework = type(self).__name__
        pass
    
    def getFilePath(self):
        filepath = _C.FRAMEWORK_DIR + '/' + self.framework + '/' + self.framework + '.json'
        exists = os.path.exists(filepath)
        if not exists:
            return False
            
        return filepath
        
    def readFile(self):
        p = self.getFilePath()
        if p == False:
            print(filepath + " not exists, skip framework generation")
            return False
        
        arr = json.loads(open(p).read())
        print(arr)
    
    def generateMetaData(self):
        pass
    
    def generateMappingInformation(self):
        pass