# Shared Access Benchmark

## Overview

The Shared Access benchmark evaluates how GCP resources are shared across projects and organizations. Proper resource sharing controls are essential for maintaining security boundaries and preventing unauthorized access.

## Categories of Controls

### Service Account Controls
- **Cross-Project Service Account Use**: Identifies service accounts that are used across different projects.

### Network Controls
- **VPC Shared Outside Organization**: Detects VPC networks that are shared with projects outside the trusted organization.

### Key Management Controls
- **KMS Keys Shared Outside Organization**: Identifies Cloud KMS keys that are shared with untrusted projects.

## Best Practices

1. **Service Account Management**
   - Keep service accounts within their project boundaries
   - Use minimal IAM roles for service accounts
   - Regularly rotate service account keys
   - Monitor service account usage

2. **Shared VPC Configuration**
   - Limit Shared VPC access to trusted projects
   - Implement proper IAM roles for Shared VPC
   - Document all shared network resources
   - Regular audit of shared VPC configurations

3. **Key Management**
   - Restrict KMS key access to trusted projects
   - Use separate keys for different environments
   - Implement key rotation policies
   - Monitor key usage and access patterns

## References

- [Service Account Best Practices](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Shared VPC Documentation](https://cloud.google.com/vpc/docs/shared-vpc)
- [Cloud KMS Security](https://cloud.google.com/kms/docs/key-management-best-practices) 