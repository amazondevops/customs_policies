from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(SCRIPT_DIR, '../JG_AWS_SG_O1_Whitelist_resources.txt')

class NonPublicPort80Check(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure AWS security groups do not have port 80 open to everywhere"
        id = "JG_AWS_SG_O1"
        supported_resources = ("aws_security_group_rule",)
        categories = (CheckCategories.NETWORKING,)
        guideline = "Port 80 should not be open to everywhere in security group rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)
        self.whitelist_set = self.load_whitelist()

    def load_whitelist(self) -> set[str]:
        whitelist_set = set()
        if os.path.isfile(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
            with open(WHITELIST_FILE, 'r') as f:
                whitelist_set = {line.strip() for line in f}
        return whitelist_set

    def scan_resource_conf(self, conf) -> CheckResult:
        resource_name = conf.get('__address__')
        if resource_name in self.whitelist_set:
            print(f"Skipping checks for whitelisted resource {resource_name}")
            return CheckResult.SKIPPED
        
        if conf.get('type') == ['ingress']:
            #print("entered to this block")
            cidr_blocks = conf.get("cidr_blocks", [])
            from_port = conf.get("from_port", [])
            to_port = conf.get("to_port", [])
            # Ensure CIDR blocks, from_port, and to_port are valid and contain data
            if cidr_blocks and any("0.0.0.0/0" in block for block in cidr_blocks):
                if 80 in from_port and 80 in to_port:
                    print(f"Found port 80 open to 0.0.0.0/0 in ingress rules for resource {resource_name}")
                    return CheckResult.FAILED
        
        return CheckResult.PASSED

non_public_port_80_check = NonPublicPort80Check()
