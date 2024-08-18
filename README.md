## Inspector Parser for ECR

AWS Inspector is a security service managed by AWS, that can detect software and network related vulnerabilities, along with generating findings related to these resources
- Container Images from Elastic Container Registry (ECR)
- AWS Lambda
- EC2 Instances


Reporting in AWS Inspector requires KMS and S3 Bucket initialization, which is a hassle if you looking for a quick workaround to get your findings imported in DefectDojo. Additionally, `list-findings` API call lets you query the generated findings from AWS Inspector.

However, the current release of DefectDojo doesn't support the JSON format in which findings are presented by AWS Inspector using `list-findings` API call. 


This fork of DefectDojo modifies the parser to support the `list-findings` API call response format for **ECR** related findings.


```bash
aws inspector2 list-findings --region="north-virginia" --filter-criteria '{"ecrImageRepository":[{"comparison": "EQUALS", "value": "ecr-repo-name"}]}' > report.json

# report.json can now be imported in dashboard under 'AWS Security Hub Scan' scanner type
```