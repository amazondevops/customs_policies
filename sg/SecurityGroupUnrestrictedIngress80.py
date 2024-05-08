

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import os

# Get the absolute path of the whitelist file relative to the script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(SCRIPT_DIR, '../JG_AWS_SG_O1_Whitelist_resources.txt')

class NonPublicPort80Check(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure AWS security groups do not have port 80 open to everywhere"
        id = "JG_AWS_SG_O1"
        supported_resources = ("aws_security_group",)
        categories = (CheckCategories.NETWORKING,)
        guideline = "Port 80 should not be open to everywhere in security group rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)
        self.whitelist_set = self.load_whitelist()
        #print("dddddd")

    def load_whitelist(self) -> set[str]:
        #print("lwwlwlwlwlwl")
        whitelist_set = set()
        if os.path.isfile(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
            with open(WHITELIST_FILE, 'r') as f:
                whitelist_set = {line.strip() for line in f}
        return whitelist_set

    def scan_resource_conf(self, conf) -> CheckResult:
        #print("sssss")
        #print("________1", conf, "------------2")
        resource_name = conf.get('__address__')
        if resource_name in self.whitelist_set:
            print(f"Skipping checks for whitelisted resource {resource_name}")
            return CheckResult.SKIPPED
        
        ingress_rules = conf.get("ingress")
        #print(ingress_rules)
        if ingress_rules:
            for rule in ingress_rules:
                from_ports = rule.get("from_port")
                to_ports = rule.get("to_port")
                # Ensure from_ports and to_ports are lists
                if isinstance(from_ports, list) and isinstance(to_ports, list):
                    for from_port, to_port in zip(from_ports, to_ports):
                        # Check if port 80 is open to 0.0.0.0/0
                        if from_port == 80 and to_port == 80:
                            cidr_blocks = rule.get("cidr_blocks")
                            if cidr_blocks and any("0.0.0.0/0" in block for block in cidr_blocks):
                                return CheckResult.FAILED
                                break  # Exit the inner loop
                    else:
                        continue  # Continue to the next rule if port 80 check failed
                    break  # Exit the outer loop if port 80 check passed
            else:
                return CheckResult.PASSED

non_public_port_80_check = NonPublicPort80Check()




