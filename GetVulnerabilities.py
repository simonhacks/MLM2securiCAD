import nvdlib

apikey = 'd7a92abe-ec30-47ec-9cfb-fde41beb4942'
keyword = 'sicam a8000'

cpes = nvdlib.searchCPE(keyword=keyword, key=apikey, limit=2)

for cpe in cpes:
    vulns = nvdlib.searchCVE(cpeName=cpe.cpe23Uri, key=apikey)

    for vuln in vulns:
        print(vuln.impact)
        print(vuln.impact.baseMetricV3.cvssV3.attackVector)
        print(vuln.impact.baseMetricV3.cvssV3.attackComplexity)
        print(vuln.impact.baseMetricV3.cvssV3.privilegesRequired)
        print(vuln.impact.baseMetricV3.cvssV3.userInteraction)
        print(vuln.impact.baseMetricV3.cvssV3.scope)
        print(vuln.impact.baseMetricV3.cvssV3.confidentialityImpact)
        print(vuln.impact.baseMetricV3.cvssV3.integrityImpact)
        print(vuln.impact.baseMetricV3.cvssV3.availabilityImpact)
        print(vuln.impact.baseMetricV3.cvssV3.baseScore)
        print(vuln.impact.baseMetricV3.cvssV3.baseSeverity)
