# import logging 
from datetime import datetime

from dojo.models import Endpoint, Finding
# logger = logging.getLogger()
# logger.setLevel("INFO")

class Inspector:
    def __init__(self):
        self.component_name = None
    def get_item(self, finding: dict, test):
        finding_id = finding.get("findingArn", "")
        title = finding.get("Description", "")
        severity = finding.get("packageVulnerabilityDetails", {}).get("vendorSeverity", "INFORMATIONAL").title()
        mitigation = ""
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = None
        description = f"This is an Inspector Finding\n{finding.get('Description', '')}" + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**AwsAccountId:** {finding.get('awsAccountId', '')}\n"
        description += f"**Region:** {finding['resources'][0].get('region', '')}\n"
        vulnerabilities = finding.get("packageVulnerabilityDetails", [])

            # Save the CVE if it is present
        if cve := vulnerabilities.get("vulnerabilityId"):
            unsaved_vulnerability_ids.append(cve)
        for alias in vulnerabilities.get("RelatedVulnerabilities", []):
            if alias != cve:
                unsaved_vulnerability_ids.append(alias)
        # Add information about the vulnerable packages to the description and mitigation

        vulnerable_packages = vulnerabilities.get("vulnerablePackages", [])
        for package in vulnerable_packages:
            mitigation += f"Update {package.get('name', '')}-{package.get('version', '')}\n"
            if remediation := package.get("fixedInVersion", "NotAvailable"):
                mitigation += f"\n\t - Fix Version: {remediation} \n\t - Vuln Type: {vulnerabilities.get('type')} \n\t - Location: ({package.get('filePath', 'NotAvailable')}) \n\t - Package Manager: {package.get('packageManager', 'NotAvailable')}\n"
        if vendor := vulnerabilities.get("referenceUrls"):
            for url in vendor:
                if vendor_url := url:
                    references.append(vendor_url)
        if vulnerabilities.get("epss") is not None:
            epss_score = vulnerabilities["epss"].get("score")

        if finding.get("ProductFields", {}).get("aws/inspector/FindingStatus", "ACTIVE") == "ACTIVE":
            mitigated = None
            is_Mitigated = False
            active = True
        else:
            is_Mitigated = True
            active = False
            if finding.get("LastObservedAt", None):
                try:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.utcnow()
        title_suffix = ""
        hosts = []

        resources = finding.get("resources", [])[0]
        # logger.info(resources)

        # for resource in finding.get("resources", [])[0]:
        self.component_name = resources.get("type")
        hosts.append(Endpoint(host=f"{self.component_name} {resources.get('id')}"))
        if self.component_name == "AWS_ECR_CONTAINER_IMAGE":
            details = resources.get("details", {}).get("awsEcrContainerImage")
            arn = resources.get("id")
            if details:
                impact.append(f"Image ARN: {arn}")
                impact.append(f"Registry: {details.get('registry')}")
                impact.append(f"Repository: {details.get('repositoryName')}")
                impact.append(f"Image digest: {details.get('imageHash')}")
            title_suffix = f" - Image: {arn.split('/', 1)[1]}"  # repo-name/sha256:digest
        else:  # generic implementation
            resource_id = resource["id"].split(":")[-1]
            impact.append(f"Resource: {resource_id}")
            title_suffix = f" - Resource: {resource_id}"

        if remediation_rec_url := finding.get("remediation", {}).get("recommendation", {}).get("url"):
            references.append(remediation_rec_url)
        false_p = False
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            mitigation=mitigation,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            active=active,
            verified=False,
            false_p=false_p,
            unique_id_from_tool=finding_id,
            mitigated=mitigated,
            is_mitigated=is_Mitigated,
            static_finding=True,
            dynamic_finding=False,
            component_name=self.component_name,
        )
        result.unsaved_endpoints = []
        result.unsaved_endpoints.extend(hosts)
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
