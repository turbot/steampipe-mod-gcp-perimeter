# KMS Key Shared Outside Organization

This control identifies Cloud KMS keys that are shared with projects outside the trusted organization.

## Overview

Cloud KMS keys should only be shared with trusted projects within your organization. Sharing encryption keys with external projects can create security risks and complicate key management.

## Remediation

1. Remove untrusted projects from key IAM policy:
   ```bash
   gcloud kms keys remove-iam-policy-binding KEY_ID \
     --location=LOCATION \
     --keyring=KEYRING \
     --member="user:UNTRUSTED_MEMBER" \
     --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
   ```

2. Grant access to trusted projects:
   ```bash
   gcloud kms keys add-iam-policy-binding KEY_ID \
     --location=LOCATION \
     --keyring=KEYRING \
     --member="user:TRUSTED_MEMBER" \
     --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
   ```

3. Best practices for KMS key management:
   - Use separate keys for different environments
   - Implement key rotation policies
   - Monitor key usage
   - Document key sharing relationships
   - Regular audit of key permissions

4. Additional security measures:
   - Use Cloud Audit Logs
   - Implement proper IAM roles
   - Use key protection levels appropriately
   - Consider using Cloud HSM for sensitive keys

## Additional Information

- [Cloud KMS Overview](https://cloud.google.com/kms/docs/concepts)
- [Cloud KMS IAM Roles](https://cloud.google.com/kms/docs/reference/permissions-and-roles)
- [Key Management Best Practices](https://cloud.google.com/kms/docs/key-management-best-practices) 