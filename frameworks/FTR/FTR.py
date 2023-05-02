from frameworks.Framework import Framework

class FTR(Framework):
    def __init__(self, data):
        super().__init__(data)
        pass
    
if __name__ == "__main__":
    data = {}
    o = FTR(data)
    o.readFile()