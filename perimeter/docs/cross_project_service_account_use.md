# Cross-Project Service Account Use

This control identifies service accounts that are being used across different projects.

## Overview

Service accounts should generally be managed within their own projects to maintain clear security boundaries. Using service accounts across projects can lead to security risks and make it harder to manage permissions effectively.

## Remediation

1. Create project-specific service accounts:
   ```bash
   gcloud iam service-accounts create SA_NAME \
     --description="DESCRIPTION" \
     --display-name="DISPLAY_NAME"
   ```

2. Grant appropriate roles to the service account:
   ```bash
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:SA_NAME@PROJECT_ID.iam.gserviceaccount.com" \
     --role="ROLE_NAME"
   ```

3. Best practices for service accounts:
   - Create service accounts in the project where they're primarily used
   - Use minimal IAM roles
   - Regularly rotate service account keys
   - Monitor service account usage
   - Document service account purposes

4. Migration steps:
   - Identify resources using cross-project service accounts
   - Create new service accounts in appropriate projects
   - Update resource configurations
   - Remove old service account permissions

## Additional Information

- [Understanding Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)
- [Service Account Best Practices](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Managing Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys) 