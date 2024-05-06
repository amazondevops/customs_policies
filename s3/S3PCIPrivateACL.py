from __future__ import annotations

from typing import Any

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
#print(SCRIPT_DIR)
WHITELIST_FILE = os.path.join(SCRIPT_DIR, '../JG_AWS_TGA_01_Whitelist_resources.txt')

class S3PCIPrivateACL(BaseResourceCheck):
    def __init__(self) -> None:
        # Initialize with a generic name
        self.name = "Ensure Resource must contain a tag called product_v2 and terraform_managed"
        id = "JG_AWS_TGA_01"
        supported_resources = ("aws_s3_bucket", "aws_instance", "aws_vpc", "aws_subnet", "aws_network_interface", "aws_security_group", "aws_security_group_rule",)
        categories = (CheckCategories.BACKUP_AND_RECOVERY,)
        guideline = "Follow the link to get more info https://docs.prismacloud.io/en/enterprise-edition/policy-reference"
        super().__init__(name=self.name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)
        self.whitelist_set = self.load_whitelist()

    def load_whitelist(self) -> set[str]:
        whitelist_set = set()
        if os.path.isfile(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
            with open(WHITELIST_FILE, 'r') as f:
                whitelist_set = {line.strip() for line in f}
        return whitelist_set

    def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        """
        Looks for Tag values at aws_s3_bucket:
        https://www.terraform.io/docs/providers/aws/r/s3_bucket.html
        :param conf: aws_s3_bucket configuration
        :return: <CheckResult>
        """
        #print("******", conf, "******")
        if conf.get('__address__') in self.whitelist_set:
            print(f"Skipping checks for whitelisted resource {conf['__address__']}")
            return CheckResult.SKIPPED

        tags = conf.get("tags")
        if tags is None or (isinstance(tags, list) and len(tags) == 0) or (isinstance(tags, list) and isinstance(tags[0], dict) and len(tags[0]) == 0):
            return CheckResult.FAILED

        tag_dict = tags[0]
        required_tags = ["product_v2", "terraform_managed"]
        for req_tag in required_tags:
            if req_tag not in tag_dict:
                return CheckResult.FAILED

        return CheckResult.PASSED

check = S3PCIPrivateACL()
