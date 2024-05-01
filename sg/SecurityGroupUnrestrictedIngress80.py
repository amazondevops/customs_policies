from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class NonPublicPort80Check(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure AWS security groups do not have port 80 open to everywhere"
        id = "JG_AWS_SG_O1"
        supported_resources = ("aws_security_group","security_group","module.security_group","aws_security_group_rule",)
        categories = (CheckCategories.NETWORKING,)
        guideline = "Port 80 should not be open to everywhere in security group rules."
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf) -> CheckResult:
        print(conf)
        ingress_rules = conf.get("ingress")
        print("***",ingress_rules)
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

