# IAM Policy Public Access

Resources should not be publicly accessible through IAM policies as they could expose sensitive data to bad actors. This benchmark evaluates IAM policies across various GCP services to identify resources that are accessible to anyone on the internet.

IAM policies control who has what access to your GCP resources. When resources are made publicly accessible through IAM policies (using `allUsers` or `allAuthenticatedUsers`), they become available to anyone on the internet, which poses significant security risks. This benchmark helps identify such public access to ensure it aligns with your security requirements.

