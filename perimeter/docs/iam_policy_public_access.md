# IAM Policy Public Access

Resources should not be publicly accessible through IAM policies as they could expose sensitive data to bad actors. This benchmark evaluates IAM policies across various GCP services to identify resources that are accessible to anyone on the internet.

IAM policies control who has what access to your GCP resources. When resources are made publicly accessible through IAM policies (using `allUsers` or `allAuthenticatedUsers`), they become available to anyone on the internet, which poses significant security risks. This benchmark helps identify such public access to ensure it aligns with your security requirements.

The benchmark includes the following categories of controls:

1. **Storage Bucket Policies**: Checks if Cloud Storage buckets allow public access
2. **Pub/Sub Topic Policies**: Identifies Pub/Sub topics with public access
3. **Pub/Sub Subscription Policies**: Identifies Pub/Sub subscriptions with public access
4. **Pub/Sub Snapshot Policies**: Identifies Pub/Sub snapshots with public access
5. **KMS Key Policies**: Detects Cloud KMS keys with public access
6. **Cloud Run Service Policies**: Checks Cloud Run services for public access
7. **BigQuery Dataset Policies**: Identifies BigQuery datasets with public access through access settings
8. **Compute Image Policies**: Checks if Compute images allow public access
