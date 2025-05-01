# VPC Shared Outside Organization

This control identifies VPC networks that are shared with projects outside the trusted organization.

## Overview

Shared VPC networks should only be shared with trusted projects within your organization. Sharing VPC networks with external projects can create security risks and make network management more complex.

## Remediation

1. Remove untrusted projects from Shared VPC:
   ```bash
   gcloud compute shared-vpc associated-projects remove PROJECT_ID \
     --host-project=HOST_PROJECT_ID
   ```

2. Configure proper Shared VPC access:
   ```bash
   gcloud compute shared-vpc associated-projects add TRUSTED_PROJECT_ID \
     --host-project=HOST_PROJECT_ID
   ```

3. Best practices for Shared VPC:
   - Only share with trusted projects
   - Use IAM roles to control access
   - Implement proper network segmentation
   - Monitor shared VPC usage
   - Document sharing relationships

4. Additional security measures:
   - Use VPC Service Controls
   - Implement proper firewall rules
   - Enable flow logs
   - Regular audit of shared VPC configurations

## Additional Information

- [Shared VPC Overview](https://cloud.google.com/vpc/docs/shared-vpc)
- [Shared VPC IAM Roles](https://cloud.google.com/vpc/docs/shared-vpc-iam)
- [Best Practices for Shared VPC](https://cloud.google.com/vpc/docs/shared-vpc#best_practices) 