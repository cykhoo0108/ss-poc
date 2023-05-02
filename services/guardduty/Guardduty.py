import os
from botocore.exceptions import ClientError
import boto3
from guardduty_driver import GuardDutyDetail

class Guardduty:
    def __init__(self, region):
        self.region = region
        self.guardduty_client = boto3.client('guardduty', region_name=region)
        self.load_drivers()

    def get_resources(self):
        results = self.guardduty_client.list_detectors()
        detector_ids = results['DetectorIds']
        return detector_ids

    def advise(self):
        objs = {}
        detectors = self.get_resources()
        for detector in detectors:
            print(f"... (GuardDuty) inspecting {detector}")
            obj = GuardDutyDetail(detector, self.guardduty_client, self.region)
            obj.run()
            objs[f"Detector::{detector}"] = obj.get_info()
        return objs

    def load_drivers(self):
        path = os.path.dirname(os.path.realpath(__file__)) + "/drivers/"
        files = os.listdir(path)
        for file in files:
            if file[0] == ".":
                continue
            exec(open(path + file).read())
