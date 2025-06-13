# IAM Policy Public Access

Resources should not be publicly accessible through IAM policies as they could expose sensitive data to bad actors. This benchmark evaluates IAM policies across various GCP services to identify resources that are accessible to anyone on the internet.

## Overview

IAM policies control who has what access to your GCP resources. When resources are made publicly accessible through IAM policies (using `allUsers` or `allAuthenticatedUsers`), they become available to anyone on the internet, which poses significant security risks. This benchmark helps identify such public access to ensure it aligns with your security requirements.

## Categories of Controls

The benchmark includes the following categories of controls:

1. **Storage Bucket Policies**: Checks if Cloud Storage buckets allow public access
2. **Pub/Sub Topic Policies**: Identifies Pub/Sub topics with public access
3. **KMS Key Policies**: Detects Cloud KMS keys with public access
4. **Cloud Function Policies**: Monitors Cloud Functions for public access
5. **Cloud Run Service Policies**: Checks Cloud Run services for public access
6. **BigQuery Dataset Policies**: Identifies BigQuery datasets with public access through access settings

## Best Practices

- Never grant public access (`allUsers` or `allAuthenticatedUsers`) to sensitive resources
- Use signed URLs or signed policy documents for temporary public access to Cloud Storage
- Implement Cloud IAP for controlled public access to applications
- Use VPC Service Controls to restrict resource access
- Regularly audit and review IAM policies for public access
- Document and maintain an inventory of resources that require public access 