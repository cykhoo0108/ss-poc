from collections import defaultdict
from PageBuilder import PageBuilder
import re

class GuardDutyPageBuilder(PageBuilder):
    DATASOURCE = [
        'FlowLogs', 'CloudTrail', 'DnsLogs', 'S3Logs', ['Kubernetes', 'AuditLogs'],
        ['MalwareProtection', 'ScanEc2InstanceWithFindings']
    ]
    SERVICESUMMARY_DEFAULT = {
        'EC2': 0,
        'IAMUser': 0,
        'Kubernetes': 0,
        'S3': 0,
        'Malware': 0,
        'RDS': 0
    }

    def __init__(self):
        self.template = 'default'
        self.statSummary = {}
        self.findings = []
        self.settings = []
        self.__gdProcess()

    def __gdProcess(self):
        self.statSummary = {'services': GuardDutyPageBuilder.SERVICESUMMARY_DEFAULT}

        detail = self.reporter.getDetail()
        for region, detectors in detail.items():
            findings = ''
            for detectorId, detector in detectors.items():
                if 'Findings' in detector:
                    findings = self.__gdProcessFinding(detector['Findings']['value'])

                self.settings[region] = self.__gdProcessGeneral(detector['FreeTrial']['value'], detector['Settings']['value']['Settings'], detector['UsageStat']['value'])

            if findings:
                self.findings.append(findings['detail'])

                self.statSummary[region] = findings['stat']['severity']
                for serv, val in findings['stat']['services'].items():
                    self.statSummary['services'][serv] += val

    def __gdProcessFinding(self, findings):
        if not findings:
            return

        arr = {
            'stat': {
                'severity': {},
                'services': GuardDutyPageBuilder.SERVICESUMMARY_DEFAULT.copy()
            }
        }

        findings_by_severity = {8: defaultdict(list), 5: defaultdict(list), 2: defaultdict(list)}

        high = len(findings[8]) if 8 in findings else 0
        medium = len(findings[5]) if 5 in findings else 0
        low = len(findings[2]) if 2 in findings else 0

        arr['stat']['severity'] = {
            'HIGH': high,
            'MEDIUM': medium,
            'LOW': low
        }

        severity_modes = [8, 5, 2]
        patterns = r"\w+"
        for severity in severity_modes:
            if severity not in findings:
                continue

            for topic, detail in findings[severity].items():
                result = re.findall(patterns, topic)
                service_type = result[1]

                if result[0] == 'Execution':
                    service_type = 'Malware'

                findings_by_severity[severity][service_type][topic] = detail

            for service, detail in findings_by_severity[severity].items():
                arr['stat']['services'][service] += len(findings_by_severity[severity][service])

        arr['detail'] = findings_by_severity
        return arr

    def __gd_process_general(self, free_trial, settings, usage_stat):
        empty_array = {
            'FreeTrial': -1,
            'Enabled': None,
            'Usage': 0
        }
        MAPPED = {
            'FLOW_LOGS': 'FlowLogs',
            'CLOUD_TRAIL': 'CloudTrail',
            'DNS_LOGS': 'DnsLogs',
            'S3_LOGS': 'S3Logs',
            'KUBERNETES_AUDIT_LOGS': 'Kubernetes:AuditLogs',
            'EC2_MALWARE_SCAN': 'MalwareProtection:ScanEc2InstanceWithFindings'
        }
        arr = {}
        for ds in GuardDutyPageBuilder.DATASOURCE:
            if isinstance(ds, list):
                key = ds[0] + ':' + ds[1]
                arr[key] = empty_array.copy()

                arr[key]['FreeTrial'] = free_trial[ds[0]][ds[1]]['FreeTrialDaysRemaining'] if free_trial[ds[0]][ds[1]]['FreeTrialDaysRemaining'] else 'N/A'

                if ds[0] == 'MalwareProtection':
                    arr[key]['Enabled'] = self.__generate_enabled_icon(settings[ds[0]][ds[1]]['EbsVolumes']['Status'])
                else:
                    arr[key]['Enabled'] = self.__generate_enabled_icon(settings[ds[0]][ds[1]]['Status'])
            else:
                arr[ds] = empty_array.copy()
                arr[ds]['FreeTrial'] = free_trial[ds]['FreeTrialDaysRemaining'] if free_trial[ds]['FreeTrialDaysRemaining'] else 'N/A'

                ds_name = ds if ds != 'DnsLogs' else 'DNSLogs'
                arr[ds]['Enabled'] = self.__generate_enabled_icon(settings[ds_name]['Status'])

        total = 0
        for stat in usage_stat:
            amount = round(stat['Total']['Amount'], 4)
            ds = MAPPED[stat['DataSource']]
            arr[ds]['Usage'] = amount

            total += amount

        arr['Total'] = total
        return arr
    
    def __generate_enabled_icon(self, status):
        icon = 'check-circle' if status == 'ENABLED' else 'ban'
        return f"<i class='nav-icon fas fa-{icon}'></i>"
    
    def buildContentSummary(self):
        output = []
    
        # Summary Row
        data_sets = {}
        labels = ['HIGH', 'MEDIUM', 'LOW']
        for region, stat in self.statSummary.items():
            if region == 'services':
                continue
    
            data_sets[region] = list(stat.values())
    
        html = self.generateBarChart(labels, data_sets)
        card = self.generateCard(self.getHtmlId('hmlStackedChart'), html, cardClass='warning', title='By Criticality', collapse=True)
        items = [[card, '']]
    
        html = self.generateDonutPieChart(self.statSummary['services'], 'servDoughnut')
        card = self.generateCard(self.getHtmlId('servChart'), html, cardClass='warning', title='By Category', collapse=True)
        items.append([card, ''])
    
        output.append(self.generateRowWithCol(6, items, "data-context='gdReport'"))
    
        # Usage/Settings Table
        tab = [
            "<table class='table table-sm'>",
            "<thead><tr><th>Region</th>"
        ]
    
        for ds in self.DATASOURCE:
            if isinstance(ds, list):
                ds = ':'.join(ds)
            tab.append("<th>{}</th>".format(ds.replace(':', '<br>')))
    
        tab.append("<th>Total</th>")
        tab.append("</tr></thead>")
        tab.append("<tbody><tr>")
    
        for region, o in self.settings:
            tab.append("<tr>")
            tab.append("<td>{}</td>".format(region))
    
            for ds in self.DATASOURCE:
                if isinstance(ds, list):
                    ds = ':'.join(ds)
    
                msg = "-"
                if ds in o:
                    d = o[ds]
                    has_trial = "({}D)".format(d['FreeTrial']) if d['FreeTrial'] > 0 else ""
                    msg = "{} ${:.4f}{}".format(d['Enabled'], d['Usage'], has_trial)
    
                tab.append("<td>{}</td>".format(msg))
    
            tab.append("<td><b>${}</b></td>".format(o['Total']))
            tab.append("</tr>")
    
        tab.append("</tbody>")
        tab.append("</table>")
    
        html = ''.join(tab)
        card = self.generateCard(self.getHtmlId('settingTable'), html, cardClass='info', title='Current Settings', collapse=True)
        items = [[card, '']]
    
        output.append(self.generateRowWithCol(12, items, "data-context='settingTable'"))
    
        return output
    
    def buildContentDetail(self):
        output = []
    
        for region, ds_list in self.detailFindings.items():
            items = []
            for ds, findings in ds_list.items():
                findings = self.groupFindings(findings)
                html = self.buildFindingsList(findings)
                card = self.generateCard(self.getHtmlId("findingsList"), html, cardClass="danger", title="By Category", collapse=True)
                items.append([card, ""])
    
            row = self.generateRowWithCol(6, items, "data-context='findings'")
            output.append(row)
    
        return output


    def __groupFindings(self, findings):
        grouped_findings = {}
    
        for finding in findings:
            category = finding["Category"]
    
            if category not in grouped_findings:
                grouped_findings[category] = []
    
            grouped_findings[category].append(finding)
    
        return grouped_findings
    
    
    def __buildFindingsList(self, grouped_findings):
        output = []
    
        for category, findings in grouped_findings.items():
            tab = [
                "<table class='table table-sm'>",
                "<thead><tr><th>Finding</th><th>Severity</th><th>Resource</th><th>Region</th><th>Account</th></tr></thead>",
                "<tbody>"
            ]
    
            for finding in findings:
                tab.append("<tr>")
                tab.append("<td>{}</td>".format(finding["Title"]))
                tab.append("<td>{}</td>".format(finding["Severity"]))
                tab.append("<td>{}</td>".format(finding["Resource"]))
                tab.append("<td>{}</td>".format(finding["Region"]))
                tab.append("<td>{}</td>".format(finding["Account"]))
                tab.append("</tr>")
    
            tab.append("</tbody>")
            tab.append("</table>")
    
            html = ''.join(tab)
            card = self.generateCard(self.getHtmlId("findingsTable"), html, cardClass="danger", title=category, collapse=True)
            items = [[card, ""]]
    
            output.append(self.generateRowWithCol(12, items, "data-context='findingsList'"))
    
        return output
