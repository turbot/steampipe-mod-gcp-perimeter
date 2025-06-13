# IAM Policy Shared Access

IAM policies should be carefully managed to prevent unintended sharing of resources across projects and organizations. This benchmark evaluates IAM policies across various GCP services to identify resources that are shared with external entities.

## Overview

IAM policies control who has what access to your GCP resources. When resources are shared through IAM policies with external entities (service accounts, users, groups, or domains), it increases the risk of unauthorized access and potential security breaches. This benchmark helps identify such shared access to ensure it aligns with your security requirements.

## Categories of Controls

The benchmark includes the following categories of controls:

1. **Service Account IAM Policies**: Checks if service accounts are shared with external entities
2. **Storage Bucket IAM Policies**: Identifies Cloud Storage buckets shared outside the project
3. **Pub/Sub Topic IAM Policies**: Detects Pub/Sub topics with external access
4. **KMS Key IAM Policies**: Monitors Cloud KMS keys shared with external entities
5. **Cloud Function IAM Policies**: Checks Cloud Functions shared with external identities
6. **Cloud Run IAM Policies**: Identifies Cloud Run services with external access

## Best Practices

- Regularly review and audit IAM policies for shared access
- Follow the principle of least privilege when granting access
- Use service account impersonation instead of direct service account sharing
- Consider using VPC Service Controls to restrict resource access
- Document and maintain an inventory of approved shared resources 