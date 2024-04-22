# from __future__ import annotations

# from typing import Any

# from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
# from checkov.common.models.enums import CheckResult, CheckCategories


# class S3PCIPrivateACL(BaseResourceCheck):
#     def __init__(self) -> None:
#         name = "Ensure Bucket must contain a tag called product_v2 and terraform_managed"
#         id = "CKV_AWS_999"
#         supported_resources = ("aws_s3_bucket",)
#         categories = (CheckCategories.BACKUP_AND_RECOVERY,)
#         guideline = "Follow the link to get more info https://docs.prismacloud.io/en/enterprise-edition/policy-reference"
#         super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

#     def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
#         """
#         Looks for Tag values at aws_s3_bucket:
#         https://www.terraform.io/docs/providers/aws/r/s3_bucket.html
#         :param conf: aws_s3_bucket configuration
#         :return: <CheckResult>
#         """
#         tags = conf.get("tags")
#         if tags is None or (isinstance(tags, list) and len(tags) == 0) or (isinstance(tags, list) and isinstance(tags[0], dict) and len(tags[0]) == 0):
#             print("return CheckResult.FAILED-1")
#             return CheckResult.FAILED  
#             exit()

#         # Assuming you only have one dictionary in the list
#         tag_dict = tags[0]

#         required_tags = ["product_v2", "terraform_managed"]
#         for req_tag in required_tags:
#             if req_tag not in tag_dict:
#                 print(f"Tag '{req_tag}' not found.")
#                 print("return CheckResult.FAILED-2")
#                 return CheckResult.FAILED
#                 exit()

#         print("return CheckResult.PASSED-3")
#         return CheckResult.PASSED

# check = S3PCIPrivateACL()

from __future__ import annotations

from typing import Any

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class S3PCIPrivateACL(BaseResourceCheck):
    def __init__(self) -> None:
        # Initialize with a generic name
        self.name = "Ensure Bucket must contain a tag called product_v2 and terraform_managed"
        id = "CKV_AWS_999"
        supported_resources = ("aws_s3_bucket",)
        categories = (CheckCategories.BACKUP_AND_RECOVERY,)
        guideline = "Follow the link to get more info https://docs.prismacloud.io/en/enterprise-edition/policy-reference"
        super().__init__(name=self.name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        """
        Looks for Tag values at aws_s3_bucket:
        https://www.terraform.io/docs/providers/aws/r/s3_bucket.html
        :param conf: aws_s3_bucket configuration
        :return: <CheckResult>
        """
        tags = conf.get("tags")
        if tags is None or (isinstance(tags, list) and len(tags) == 0) or (isinstance(tags, list) and isinstance(tags[0], dict) and len(tags[0]) == 0):
            self.name = "No tags found for the S3 bucket"
            return CheckResult.FAILED

        # Assuming you only have one dictionary in the list
        tag_dict = tags[0]

        required_tags = ["product_v2", "terraform_managed"]
        for req_tag in required_tags:
            if req_tag not in tag_dict:
                self.name = f"Tag '{req_tag}' not found for the S3 bucket"
                return CheckResult.FAILED

        return CheckResult.PASSED

check = S3PCIPrivateACL()
