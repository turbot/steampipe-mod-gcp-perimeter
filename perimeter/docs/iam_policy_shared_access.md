# IAM Policy Shared Access

IAM policies should be carefully managed to prevent unintended sharing of resources across projects and organizations. This benchmark evaluates IAM policies across various GCP services to identify resources that are shared with external entities.

IAM policies control who has what access to your GCP resources. When resources are shared through IAM policies with external entities (service accounts, users, groups, or domains), it increases the risk of unauthorized access and potential security breaches. This benchmark helps identify such shared access to ensure it aligns with your security requirements.

The benchmark includes the following categories of controls:

## Identity & Access
- **Service Account IAM Policies** - Ensures service account IAM policies only grant access to trusted principals
- **Billing Account IAM Policies** - Ensures billing account IAM policies only grant access to trusted principals

## Storage & Databases
- **Cloud Storage Bucket IAM Policies** - Ensures storage bucket IAM policies only grant access to trusted principals
- **Bigtable Instance IAM Policies** - Ensures Bigtable instance IAM policies only grant access to trusted principals

## Compute & Serverless
- **Compute Instance IAM Policies** - Ensures Compute Engine instance IAM policies only grant access to trusted principals
- **Compute Disk IAM Policies** - Ensures Compute disk IAM policies only grant access to trusted principals
- **Compute Image IAM Policies** - Ensures Compute image IAM policies only grant access to trusted principals
- **Compute Node Group IAM Policies** - Ensures Compute node group IAM policies only grant access to trusted principals
- **Compute Node Template IAM Policies** - Ensures Compute node template IAM policies only grant access to trusted principals
- **Compute Resource Policy IAM Policies** - Ensures Compute resource IAM policies only grant access to trusted principals
- **Compute Subnetwork IAM Policies** - Ensures Compute subnetwork IAM policies only grant access to trusted principals
- **Cloud Function IAM Policies** - Ensures Cloud Function IAM policies only grant access to trusted principals
- **Cloud Run Service IAM Policies** - Ensures Cloud Run service IAM policies only grant access to trusted principals
- **Cloud Run Job IAM Policies** - Ensures Cloud Run job IAM policies only grant access to trusted principals

## Messaging & Integration
- **Pub/Sub Topic IAM Policies** - Ensures Pub/Sub topic IAM policies only grant access to trusted principals
- **Pub/Sub Subscription IAM Policies** - Ensures Pub/Sub subscription IAM policies only grant access to trusted principals

## Security & Encryption
- **KMS Key IAM Policies** - Ensures Cloud KMS key IAM policies only grant access to trusted principals
- **KMS Key Ring IAM Policies** - Ensures Cloud KMS key ring IAM policies only grant access to trusted principals

## Configuration

This benchmark uses configurable variables to define trusted principals:

- `trusted_users` - List of trusted Google Account emails
- `trusted_groups` - List of trusted Google Groups  
- `trusted_service_accounts` - List of trusted service accounts
- `trusted_domains` - List of trusted Google Workspace domains

Resources with IAM policies granting access only to these trusted principals will be marked as compliant, while resources with access granted to untrusted principals will be flagged as non-compliant.
