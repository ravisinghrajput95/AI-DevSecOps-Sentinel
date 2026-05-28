from backend.memory import memory
from backend.rag import search, build_context
import re

# =========================================================
# KNOWLEDGE SUFFIX PATTERNS — compiled once at module load
# Catches: "X explained", "X best practices", "X vs Y",
# "X and Y explained", "Secure X best practices", etc.
# These run BEFORE hard triggers in is_general_question.
# =========================================================
_KNOWLEDGE_SUFFIX_PATTERNS = [
    re.compile(r'.+\s+explained\s*\??$', re.IGNORECASE),
    re.compile(r'^(secure\s+)?[\w\s\./\-]+\s+best\s+practices\s*\??$', re.IGNORECASE),
    re.compile(r'.+\s+overview\s*\??$', re.IGNORECASE),
    re.compile(r'.+\s+tutorial\s*\??$', re.IGNORECASE),
    re.compile(r'.+\s+guide\s*\??$', re.IGNORECASE),
    re.compile(r'^[\w\s\./\-\(\)]+ vs\.? [\w\s\./\-\(\)]+\s*\??$', re.IGNORECASE),
    re.compile(r'^[\w\s\./\-\(\)]+ versus [\w\s\./\-\(\)]+\s*\??$', re.IGNORECASE),
    re.compile(r'^compare [\w\s\./\-]+ (and|to|with|vs) [\w\s\./\-]+\s*\??$', re.IGNORECASE),
    re.compile(r'^[\w\s\./\-]+ and [\w\s\./\-]+ explained\s*\??$', re.IGNORECASE),
    re.compile(r'^[\w\s\./\-]+ (networking|security|architecture)\s+explained\s*\??$', re.IGNORECASE),
    re.compile(r'^[\w\s\./\-]+ (networking|security|architecture)\s*\??$', re.IGNORECASE),
]

_KNOWLEDGE_CANCEL_WORDS = {
    "this", "these", "the file", "the repo", "the project",
    "the code", "the config", "the pipeline", "the dockerfile",
    "the terraform", "the chart", "the manifest",
    "uploaded", "my file", "my repo", "my code",
    "above", "attached", "provided", "given",
}

def _matches_knowledge_suffix(msg: str) -> bool:
    """
    Returns True if the message is a general knowledge/learning
    question — NOT a request to analyse uploaded files.
    
    Two checks:
    1. Cancel — if message references uploaded content → False
    2. Match  — if message matches any knowledge pattern → True
    """

    # ── Cancel: references uploaded content ──────────────
    file_refs = [
        "this file", "the file", "these files",
        "this repo", "the repo", "this repository",
        "this project", "the project",
        "this code", "the code",
        "this config", "the config",
        "this pipeline", "the pipeline",
        "this dockerfile", "the dockerfile",
        "this terraform", "the terraform",
        "this chart", "the chart",
        "this manifest", "the manifest",
        "uploaded", "my file", "my repo",
        "my code", "my config",
    ]
    for ref in file_refs:
        if ref in msg:
            return False

    # ── Match: ends with knowledge signal ────────────────
    knowledge_suffixes = (
        " explained", " best practices", " overview",
        " tutorial", " guide", " concepts", " fundamentals",
        " basics", " cheatsheet", " exam", " certification",
        " interview", " interview questions", " architecture",
        " patterns", " strategies", " roadmap",
    )
    clean = msg.rstrip("?! ")
    for suffix in knowledge_suffixes:
        if clean.endswith(suffix):
            return True

    # ── Match: starts with knowledge signal ──────────────
    knowledge_prefixes = (
        "what is ", "what are ", "what was ", "what were ",
        "what's the ", "whats the ",
        "how does ", "how do ", "how can ", "how should ",
        "how to ",
        "explain ", "describe ", "define ",
        "tell me about ", "tell me how ",
        "help me understand ", "help me learn ",
        "help me prepare ", "help me study ",
        "help me pass ", "help me get ",
        "i want to learn ", "i want to understand ",
        "i need to learn ", "i need to understand ",
        "teach me ", "show me how ",
        "can you explain ", "can you describe ",
        "can you help me ",
        "could you explain ", "could you describe ",
        "please explain ", "please describe ",
        "compare ", "comparing ",
        "difference between ", "differences between ",
        "pros and cons", "advantages of ", "disadvantages of ",
        "when should i use ", "when to use ",
        "why use ", "why is ", "why does ", "why are ",
        "give me an example ", "give an example ",
        "introduction to ", "intro to ",
        "overview of ", "summary of ",
        "tutorial on ", "guide to ", "guide for ",
        "best practices for ", "best practices of ",
        "recommend ", "which tool ", "what tool ",
        "prepare for ", "preparing for ", "study for ",
        "learn ", "learning ",
        "understand ",
    )
    for prefix in knowledge_prefixes:
        if msg.startswith(prefix):
            return True

    # ── Match: X vs Y pattern ────────────────────────────
    if (
        " vs " in msg or
        " vs. " in msg or
        " versus " in msg or
        " compared to " in msg or
        " or " in msg and len(msg.split()) <= 8
    ):
        # Make sure it's not referencing files
        if not any(ref in msg for ref in file_refs):
            return True

    return False

# =========================================================
# SYSTEM PROMPT
# =========================================================

SYSTEM_PROMPT = """
# AI DevSecOps Sentinel — Senior DevOps & DevSecOps AI Assistant

## Identity & Role

You are **AI DevSecOps Sentinel**, a Staff-level DevOps and DevSecOps engineer with 15+ years of equivalent expertise. You produce enterprise-grade security intelligence — not just findings, but contextual reasoning, compliance mapping, exploitability scoring, and threat narratives. You think like a principal security engineer AND a threat analyst simultaneously.

---

## ABSOLUTE OUTPUT RULES — NEVER VIOLATE

### Rule 1 — Always cite exact values
WRONG: "mysql-connector-java may contain vulnerabilities"
RIGHT: "mysql-connector-java 5.1.25 is outdated — known vulnerabilities reported in this version, upgrade to 8.0.33"

### Rule 2 — Always show exact code snippet causing the issue
Show the actual block from the file with the problem line clearly visible.

### Rule 3 — Always show the fix as real usable code
WRONG: "Replace with specific IP range"
RIGHT: Show actual corrected block with real values substituted, ready to copy-paste into the file.

### Rule 4 — Never use vague language
BANNED: "typically used for", "may contain", "could potentially", "consider reviewing",
"might want to", "production readiness", "DevOps maturity", "affected by CVE-XXXX" (unless file contains it)

### Rule 5 — Never fabricate CVE IDs
Use: "Known vulnerabilities reported in older versions of this library" — never invent CVE numbers.

### Rule 6 — Always include Positive Findings
Every analysis must acknowledge what is correctly configured with specific values.

### Rule 7 — Never hallucinate
Only reference content present in the provided files. If absent: "This is not defined in the provided files."

### Rule 8 — Always include line numbers
Format: filename:line or filename:line-line — mandatory for every Security Finding.

### Rule 9 — Detect real secrets
Patterns to flag as Critical [SECRETS] [Confidence: HIGH]:
- AWS keys: AKIA[0-9A-Z]{16}
- GitHub PATs: ghp_[a-zA-Z0-9]{36}
- Private keys: -----BEGIN RSA PRIVATE KEY-----
- Plaintext: password=, passwd=, api_key=, token=, secret= with non-placeholder values
- Connection strings with embedded credentials
Redact the value in output.

### Rule 10 — Confidence scoring with reasoning
Every finding must include:
[Confidence: HIGH/MEDIUM/LOW]
Confidence Reason:
- Bullet explaining exactly WHY this confidence level — grounded in file evidence
- Maximum 3 bullets

Confidence levels:
- HIGH   — directly visible in file (hardcoded secret, explicit misconfiguration, exact bad value)
- MEDIUM — inferred from context (outdated dependency, missing recommended config)
- LOW    — architectural inference (assumed behavior not directly visible)

### Rule 11 — Finding categories
[SECRETS] [MISCONFIGURATION] [VULNERABLE-DEPENDENCY] [CI-CD]
[KUBERNETES] [DOCKER] [TERRAFORM] [COMPLIANCE] [NETWORK]

### Rule 12 — Compliance mapping
For every High and Critical finding, map to relevant standards:
Compliance: CWE-XXX | OWASP A0X | CIS X.X | NIST AC-X | MITRE TXXXX
Only map standards that genuinely apply — do not force-fit.

Common mappings:
- Hardcoded secrets: CWE-798 | OWASP A07 | CIS 2.1 | NIST IA-5
- Open CIDR / public exposure: CWE-732 | OWASP A05 | CIS 4.1 | NIST SC-7 | MITRE T1190
- Missing encryption: CWE-311 | OWASP A02 | CIS 2.2 | NIST SC-8
- Privileged containers: CWE-250 | OWASP A05 | CIS 5.2 | NIST AC-6
- Vulnerable dependency: CWE-1035 | OWASP A06 | NIST SI-2
- Wildcard IAM: CWE-732 | OWASP A01 | CIS 1.16 | NIST AC-3
- Missing auth: CWE-306 | OWASP A07 | NIST IA-2
- Insecure CI/CD: CWE-829 | OWASP A08 | NIST SA-11

### Rule 13 — Exploitability score
Every finding must include:
Exploitability: HIGH / MEDIUM / LOW
Reason: One sentence explaining why.
HIGH = exploit exists, no auth needed, directly reachable
MEDIUM = requires specific conditions or access
LOW = theoretical, requires chained complex conditions

### Rule 14 — Why it matters (educational layer)
Every High and Critical finding must include:
Why it matters: Real-world exploitation path in 1-2 sentences.
Focus on WHAT an attacker can DO, not just that it is insecure.

### Rule 15 — Evidence
Every finding must include:
Evidence: filename:line — exact quoted value from the file proving this finding.

### Rule 16 — Blast Radius
Every High and Critical finding must include:
Blast Radius:
- Bullet list of systems, components, data, services affected if exploited

### Rule 17 — Fix snippets must be production-ready
WRONG: Replace <specific_value> with your value
RIGHT: Complete corrected block with secure example values and comment explaining the change.
Use # BAD / # FIX diff format for secrets and configuration changes.

### Rule 18 — Cross-file relationship analysis
When multiple files uploaded, check:
- Port consistency across Dockerfile, K8s service, README, app config
- Secret references in app config vs K8s secret mounts
- Image in Dockerfile vs image in K8s deployment
- Environment variables declared vs actually mounted
- IAM roles vs resources they access
- Security groups vs instances they protect
Report consistency as Positive Finding, conflicts as findings.

### Rule 19 — File-type intelligence
Detect stack and adapt analysis:
- Terraform: open CIDRs, missing encryption, wildcard IAM, public S3, missing state locking
- Kubernetes: privileged pods, missing securityContext, exposed services, no resource limits
- Dockerfiles: root user, latest tags, secrets in ENV/ARG, no HEALTHCHECK, no non-root USER
- CI/CD: hardcoded secrets, no secret scanning, unpinned actions, no SAST step
- Java/Maven: vulnerable deps, missing OWASP plugin, outdated Spring/Hibernate
- Helm: insecure default values, exposed NodePort services, missing network policies

### Rule 20 — Dependency relationship map
When analysing a repository, detect and show infrastructure relationships:
GitHub Actions → Docker Build → Registry → K8s Deployment → Database via Security Group
This must be derived from actual file contents only.

### Rule 21 — Risk score
For repository analysis, calculate:
Security Score: XX/100
Start at 100. Deduct:
- Each Critical finding: -15 points
- Each High finding: -8 points
- Each Medium finding: -3 points
- Each Low finding: -1 point
- Secrets exposure: additional -10
- Public network exposure (0.0.0.0/0): additional -8
- Wildcard IAM (*): additional -5

Show breakdown with reasons.

### Rule 22 — Threat narrative
After all file analyses, generate:
### Threat Narrative
3-5 sentences. Specific attack chain using actual findings, filenames, values.
How would a real attacker chain these findings to achieve data exfiltration, lateral movement, or privilege escalation?
Reference real file names and actual values found.

---

## REQUIRED OUTPUT FORMAT FOR EVERY FILE

## File Analysis: `<exact filename>`
**Stack Context**: <detected technologies from this file>

### Purpose
One sentence from actual file content.

### Technologies Detected
Bullet list from actual content.

### Important Configurations
Key configs with exact values cited.

### Positive Findings
Specific correct configurations with real values.

### Security Findings

#### Critical [CATEGORY] [Confidence: HIGH]
**[Finding Title]**
Location: filename:line

```lang
<exact code snippet from file>
```

Risk: One precise sentence using actual values.
Why it matters: Real-world exploitation path in 1-2 sentences.
Evidence: filename:line — `exact quoted value`
Exploitability: HIGH — reason in one sentence.
Blast Radius:
- affected system 1
- affected system 2
Compliance: CWE-XXX | OWASP A0X | CIS X.X | NIST XX-X | MITRE TXXXX
Confidence Reason:
- specific reason grounded in file evidence
- specific reason 2

Fix:
BAD
<insecure code>
FIX — <what was changed and why>
<secure corrected code>
````
High [CATEGORY] [Confidence: LEVEL]
[same full format as Critical]
Medium [CATEGORY] [Confidence: LEVEL]
[Finding Title]
Location: filename:line
Snippet + Risk + Evidence + Exploitability + Compliance + Fix
Low / Suggestions [CATEGORY] [Confidence: LEVEL]
[Finding Title]: Specific recommendation with real values from the file.
Recommendations Summary
Ordered by Exploitability x Severity:

[CRITICAL] [Exploitability: HIGH] Action at filename:line
[HIGH] [Exploitability: HIGH] Action at filename:line
...


REPOSITORY ZIP ANALYSIS FORMAT
Repository Analysis: <repo-name>
Stack Intelligence
Detected from actual files:

IaC: ...
Containers: ...
Orchestration: ...
CI/CD: ...
Languages: ...
Databases: ...

Secret Scan Summary
List all secrets found immediately — before any other findings.
If none: "No hardcoded secrets detected in scanned files."
Dependency Relationship Map
Infrastructure relationships detected across files:
<resource> → <resource> → <resource>
Derived from actual file contents only.
Risk Score
Security Score: XX/100
Breakdown:

Critical findings (N × -15): -XX
High findings (N × -8): -XX
Secrets exposure: -XX
Public network exposure: -XX
Wildcard IAM: -XX
Medium findings (N × -3): -XX
Low findings (N × -1): -XX
Final Score: XX/100 — Risk Level: CRITICAL / HIGH / MEDIUM / LOW

[Individual File Analyses using format above]
Cross-File Observations
Real conflicts only — with category, confidence, exploitability.
Threat Narrative
3-5 sentences. Specific attack chain using actual filenames and values.
Remediation Roadmap
Immediate (fix before next commit):
[Critical + Exploitability HIGH findings]
Short-term (this sprint):
[High findings]
Long-term (backlog):
[Medium + Low findings]

DevOps Domain Expertise
CI/CD: GitHub Actions, GitLab CI, Jenkins, CircleCI, ArgoCD, Tekton, Spinnaker, Drone CI
Containers: Docker, Podman, BuildKit, containerd, OCI standards, distroless images
Orchestration: Kubernetes, Helm, Kustomize, OpenShift, Nomad, K3s
IaC: Terraform, Pulumi, Ansible, CloudFormation, Crossplane, CDK
Cloud: AWS, GCP, Azure — compute, networking, IAM, storage, serverless, cost optimization
Observability: Prometheus, Grafana, Loki, Tempo, OpenTelemetry, Datadog, ELK/EFK, Jaeger
Security: SAST/DAST, SBOM, Trivy, Snyk, Grype, OPA/Gatekeeper, Falco, RBAC, Vault, SOPS
Networking: Istio, Linkerd, NGINX, Traefik, DNS, TLS/mTLS, network policies
Supply Chain Security: Sigstore/Cosign, SLSA framework, provenance attestation
Boundaries

Never generate real secrets. Redact found secrets, use secure placeholders in fixes.
Never invent CVE IDs. Never hallucinate file contents.
Off-topic questions unrelated to DevOps/infra/security: politely redirect in 2 sentences max.
If zip too large: state what was covered, ask what to prioritise.
If a finding confidence is LOW: state the assumption explicitly.
"""

# =========================================================
# DEVOPS TERMS — presence means never off-topic
# =========================================================
DEVOPS_TERMS = {
    "docker", "kubernetes", "k8s", "terraform", "helm", "ansible",
    "jenkins", "pipeline", "ci/cd", "github actions", "gitlab",
    "container", "pod", "deployment", "ingress", "service mesh",
    "prometheus", "grafana", "argocd", "gitops", "vault",
    "aws", "gcp", "azure", "cloud", "iam", "s3", "ec2",
    "nginx", "traefik", "istio", "linkerd", "kubectl",
    "devops", "devsecops", "sre", "platform engineering",
    "dockerfile", "image", "registry", "helm chart",
    "configmap", "namespace", "rbac", "cluster", "replica",
    "autoscale", "hpa", "vpa", "monitoring", "alerting",
    "logging", "tracing", "infrastructure", "iac", "provisioning",
    "security", "vulnerability", "cve", "sbom", "trivy",
    "port", "expose", "cidr", "firewall", "tls", "ssl",
    "checkov", "tfsec", "gitleaks", "snyk", "kubesec",
    "polaris", "kube-score", "grype", "cosign", "slsa",
    "pulumi", "cloudformation", "crossplane", "cdk",
    "loki", "tempo", "opentelemetry", "datadog", "jaeger",
    "falco", "opa", "gatekeeper", "sops", "external secrets",
    "buildkit", "containerd", "podman", "distroless",
    "spinnaker", "tekton", "drone", "circleci",
    "kustomize", "openshift", "nomad", "k3s",
    "sarif", "cwe", "owasp", "nist", "mitre", "cis",
    "sonarqube", "semgrep", "bandit", "hadolint",
    "rds", "eks", "ecs", "ecr", "lambda", "vpc",
    "alb", "nlb", "cloudfront", "route53", "secretsmanager",
    "parameterstore", "kms", "waf", "cloudtrail", "guardduty",
    "pagerduty", "oncall", "slo", "sla", "sli", "runbook",
    "terraform cloud", "atlantis", "spacelift", "env0",
    "renovate", "dependabot", "snyk", "whitesource",
    "artifactory", "nexus", "harbor", "quay",
    "cilium", "calico", "flannel", "weave",
    "velero", "longhorn", "rook", "ceph",
    "cert-manager", "external-dns", "cluster-autoscaler",
}

# =========================================================
# OFF-TOPIC PERSON NAMES
# =========================================================
OFF_TOPIC_PERSON_NAMES = {
    # Indian names / politicians / celebrities
    "geetanjali", "sunita", "priya", "rahul sharma", "rohit",
    "virat", "sachin", "amitabh", "shahrukh", "deepika",
    "priyanka chopra", "narendra modi", "kejriwal",
    "rahul gandhi", "sonia gandhi", "yogi adityanath",
    # International politicians
    "elon musk", "jeff bezos", "mark zuckerberg", "bill gates",
    "steve jobs", "warren buffett", "oprah winfrey",
    "taylor swift", "beyonce", "trump", "biden", "obama",
    "putin", "xi jinping", "boris johnson", "macron", "trudeau",
    "rishi sunak", "sunak",
    # Historical / academic figures
    "mahatma gandhi", "einstein", "newton", "charles darwin",
    "william shakespeare", "napoleon", "hitler", "mussolini",
    "abraham lincoln", "george washington", "winston churchill",
    "sigmund freud", "karl marx", "plato", "aristotle", "socrates",
    "julius caesar", "alexander the great", "cleopatra",
    # Cricketers / athletes
    "ms dhoni", "virat kohli", "sachin tendulkar", "jasprit bumrah",
    "rohit sharma", "cristiano ronaldo", "lionel messi",
    "roger federer", "rafael nadal", "novak djokovic",
    "lebron james", "michael jordan", "usain bolt",
}

# =========================================================
# OFF-TOPIC TOPIC PATTERNS
# =========================================================
OFF_TOPIC_TOPIC_PATTERNS = [
    # Geography
    "capital of ", "population of ", "currency of ",
    "where is located", "which continent is", "largest country",
    "smallest country", "longest river", "tallest mountain",
    # History / politics
    "history of india", "history of china", "history of the usa",
    "when was born", "when did he die", "when did she die",
    "president of usa", "prime minister of india",
    "prime minister of uk", "election result", "who won the election",
    "political party", "parliament of", "senate",
    # Entertainment
    "best bollywood", "best hollywood", "best movie of",
    "best series", "best song", "best album of",
    "who plays the role", "which actor", "which actress",
    "lyrics of ", "release date of the movie",
    "box office collection", "oscar winner", "grammy winner",
    "netflix series", "amazon prime show",
    # Sports
    "ipl winner", "ipl 2024", "cricket score", "live score",
    "football score", "nba score", "nfl score", "epl score",
    "world cup winner", "olympics gold medal",
    "who won the match", "match result today",
    "cricket schedule", "football schedule",
    # Food / lifestyle
    "recipe for ", "how to cook ", "calories in ",
    "best restaurant in", "what to eat", "diet plan",
    "weight loss tips", "fitness routine", "yoga poses",
    # Relationships / personal
    "relationship advice", "love advice", "how to impress",
    "how to propose", "my girlfriend", "my boyfriend",
    "dating tips", "marriage advice", "breakup advice",
    # Religion / astrology
    "horoscope for", "zodiac sign", "astrology reading",
    "which temple", "which mosque", "which church",
    "prayer for", "religious ritual",
    # Finance / stocks (non-cloud)
    "stock price of ", "share price of ", "buy or sell stock",
    "investment advice", "cryptocurrency price", "bitcoin price",
    "ethereum price", "which stock to buy", "nifty 50",
    "sensex today",
    # General trivia
    "tallest building in the world", "deepest ocean",
    "speed of light in", "distance from earth to",
    "how old is the universe", "age of the earth",
    "chemical formula of water", "periodic table element",
    "square root of ", "solve this math",
    "what is 2 plus 2", "simple interest formula",
]

# =========================================================
# GREETING DETECTION
# =========================================================
def handle_simple_greeting(user_message: str) -> bool:
    greetings = {
        "hi", "hello", "hey", "hiya", "howdy",
        "good morning", "good afternoon", "good evening", "good day",
        "what's up", "whats up", "sup", "yo",
    }
    return user_message.lower().strip().rstrip("!.,?") in greetings


# =========================================================
# OFF-TOPIC DETECTION
# =========================================================
def is_off_topic(user_message: str) -> bool:
    """
    Returns True if the message is clearly unrelated to DevOps/tech.
    DevOps term presence overrides all other signals.
    """
    msg = user_message.lower().strip().rstrip("?!.,")

    # RULE 1 — Any DevOps term present → never off-topic
    for term in DEVOPS_TERMS:
        if term in msg:
            return False

    # RULE 2 — Known off-topic person names (exact substring match)
    for name in OFF_TOPIC_PERSON_NAMES:
        if name in msg:
            return True

    # RULE 3 — "who is X" / "who was X" with non-DevOps subject
    if msg.startswith("who is ") or msg.startswith("who was "):
        subject = msg.replace("who is ", "").replace("who was ", "").strip()
        if not any(term in subject for term in DEVOPS_TERMS):
            return True

    # RULE 4 — "tell me about X" with no DevOps subject, short phrase
    if msg.startswith("tell me about "):
        subject = msg.replace("tell me about ", "").strip()
        if not any(term in subject for term in DEVOPS_TERMS):
            if len(subject.split()) <= 5:
                return True

    # RULE 5 — Known off-topic topic patterns
    for pattern in OFF_TOPIC_TOPIC_PATTERNS:
        if pattern in msg:
            return True

    # RULE 6 — Pure math/numeric expressions
    if re.match(r'^[\d\s\+\-\*\/\^\(\)\.=]+$', msg):
        return True

    # RULE 7 — Very short messages with no tech or file signals
    words = msg.split()
    if len(words) <= 4:
        file_signals = {
            "it", "its", "this", "these", "the", "here",
            "analyse", "analyze", "review", "check", "scan",
            "file", "repo", "code", "config", "pipeline",
            "secret", "port", "image", "version", "fix",
            "audit", "deploy", "build", "run", "test",
        }
        has_file_signal = any(w in file_signals for w in words)
        has_tech = any(term in msg for term in DEVOPS_TERMS)
        if not has_file_signal and not has_tech:
            non_tech_starters = {
                "who ", "where ", "when ", "why is life",
                "how old", "how tall", "how much does",
                "what is love", "what is life", "what is god",
            }
            for starter in non_tech_starters:
                if msg.startswith(starter):
                    return True

    return False


# =========================================================
# ACKNOWLEDGEMENT DETECTION
# Short social/confirmatory messages that should never
# trigger file analysis — "great", "ok", "thanks", etc.
# =========================================================
ACKNOWLEDGEMENT_PHRASES = {

    # Casual greetings (these were missing — root cause of the bug)
    "wassup", "wazzup", "sup", "yo", "hey", "hi", "hello",
    "hiya", "howdy", "heya", "heyy", "hihi",
    "good morning", "good afternoon", "good evening", "good day",
    "what's up", "whats up", "wats up", "wat up",
    "how are you", "how r u", "how are u", "hru",
    "how's it going", "hows it going", "how is it going",
    "how are things", "how have you been", "how's everything",
    "you good", "u good", "are you ok", "are you good",
    "what's new", "whats new", "anything new",
    # Confirmations
    "ok", "okay", "k", "got it", "got that", "understood",
    "makes sense", "i see", "i understand", "fair enough",
    "fair", "noted", "alright", "alright then",
    # Positive reactions
    "great", "good", "nice", "cool", "awesome", "perfect",
    "excellent", "wonderful", "fantastic", "brilliant",
    "amazing", "love it", "love that", "looks good",
    "looks great", "sounds good", "sounds great",
    "that's great", "thats great", "that's good", "thats good",
    "that's helpful", "thats helpful", "very helpful",
    "that helps", "that helped", "helpful",
    # Gratitude
    "thanks", "thank you", "thank you so much", "ty",
    "thx", "cheers", "appreciate it", "much appreciated",
    "thanks a lot", "thanks a bunch", "thank you very much",
    "thank u", "thnks", "thnx",
    # Simple continuations
    "continue", "go on", "proceed", "go ahead",
    "sure", "yes", "yep", "yup", "yeah", "yea",
    "no", "nope", "not really", "not yet",
    "okay cool", "ok cool", "cool cool",
    "got it thanks", "got it thank you",
    "understood thanks", "makes sense thanks",
    # File upload acknowledgements
    "sure, here are the files", "here are the files",
    "here are the uploaded files", "sure here are",
    "files uploaded", "uploaded for your reference",
    "for your reference", "for reference",
    # Emoji-only or very short
    "👍", "👌", "✅", "🙏", "😊", "🔥"
}

# Max word count to even attempt acknowledgement check
_ACK_MAX_WORDS = 8


def is_acknowledgement(user_message: str) -> bool:
    """
    Returns True if the message is a short social/acknowledgement
    response that should never trigger a full file analysis pass.
    """
    msg = user_message.lower().strip().rstrip("!.,?")
    words = msg.split()

    if len(words) > _ACK_MAX_WORDS:
        return False

    # Exact match
    if msg in ACKNOWLEDGEMENT_PHRASES:
        return True

    # Starts-with match (catches "thanks a lot!" etc)
    for phrase in ACKNOWLEDGEMENT_PHRASES:
        if msg.startswith(phrase) and (
            len(msg) == len(phrase) or msg[len(phrase)] in " !.,?"
        ):
            return True

    return False


# =========================================================
# REDIRECT INTENT DETECTION
# =========================================================

# Phrases that signal a topic change ONLY when NOT followed
# by file-reference words. Kept specific to avoid false positives
# on messages like "lets discuss the uploaded files".
REDIRECT_INTENTS = [
    "discuss something else",
    "talk about something else",
    "something else",
    "change topic",
    "change the topic",
    "switch topic",
    "switch to something",
    "never mind",
    "nevermind",
    "forget that",
    "forget it",
    "let's move on",
    "lets move on",
    "different topic",
    "different question",
    "ask you something else",
    "ask something else",
    "talk about something different",
    "discuss something different",
]

# These phrases are redirect candidates ONLY if no file-reference
# word follows them — e.g. "lets discuss" alone = redirect,
# but "lets discuss the uploaded files" = file mode.
REDIRECT_INTENTS_CONDITIONAL = [
    "let's talk about",
    "lets talk about",
    "can we talk about",
    "i want to ask about",
    "i want to discuss",
    "can we discuss",
    "let's discuss",
    "lets discuss",
]

# If any of these words appear after a conditional redirect phrase,
# it means the user is referencing files — NOT changing topic.
FILE_REFERENCE_CANCELLERS = {
    "this", "these", "the", "my", "uploaded", "above",
    "file", "files", "repo", "repository", "project", "code",
    "config", "pipeline", "dockerfile", "terraform", "chart",
    "manifest", "script", "workflow", "yaml", "json", "zip",
    "it", "them", "those",
}


def is_redirect_intent(user_message: str) -> bool:
    """
    Returns True if the user wants to change the topic or move away
    from the current file analysis context.

    Three-tier check:
    1. Hard redirect phrases — always a redirect.
    2. Conditional phrases — only a redirect if followed by a
       non-file-reference word (requires at least one word after
       the phrase — bare "lets discuss" with nothing after is
       ambiguous and handled by Tier 3).
    3. Bare conditional phrases with no trailing words — only a
       redirect when no files are uploaded (unambiguous intent).
    """
    msg = user_message.lower().strip()

    # Tier 1 — hard redirect phrases, no ambiguity
    if any(phrase in msg for phrase in REDIRECT_INTENTS):
        return True

    # Tier 2 & 3 — conditional phrases
    for phrase in REDIRECT_INTENTS_CONDITIONAL:
        if phrase in msg:
            after = msg[msg.index(phrase) + len(phrase):].strip()
            words_after = after.split()

            if not words_after:
                # Tier 3 — bare phrase with nothing after it
                # e.g. "lets discuss" — ambiguous when files present.
                # Only treat as redirect if NO files are uploaded.
                if len(memory["files"]) == 0:
                    return True
                # Files present + bare phrase = user wants to discuss files
                return False

            # Tier 2 — phrase followed by words
            first_word = words_after[0]
            if first_word not in FILE_REFERENCE_CANCELLERS:
                return True

    return False


# =========================================================
# FILE MODE HARD TRIGGERS
# =========================================================
FILE_MODE_HARD_TRIGGERS = [
    # Direct file/repo references
    "this zip", "the zip", "this file", "the file", "these files",
    "this repo", "the repo", "this repository", "the repository",
    "this project", "the project", "this code", "the code",
    "this config", "the config", "this pipeline", "the pipeline",
    "this dockerfile", "this terraform", "this chart", "this manifest",
    "this script", "this workflow", "this yaml", "this json",
    "uploaded file", "uploaded files", "my file", "my files",
    "my repo", "my project", "my code", "my config",
    # DevOps file types — only when user references THE file, not the technology
    "this dockerfile", "the dockerfile",
    "this terraform", "the terraform",
    "this helm chart", "the helm chart",
    "this chart.yaml", "this values.yaml",
    "this manifest", "the manifest",
    "this jenkinsfile", "the jenkinsfile",
    "this pipeline file", "the pipeline file",
    # Security intent — specific phrases only, not bare nouns
    "hardcoded secret", "exposed secret", "leaked secret",
    "security issue in", "security problem in",
    "misconfiguration in", "insecure configuration",
    # Scan verbs — only when explicitly targeting files
    "analyse all", "analyze all", "audit all",
    "scan all", "analyse the", "analyze the",
    "audit the", "scan the",
    # Analysis intent
    "understand this", "help me understand this",
    "explain this", "what does this do", "what is this doing",
    "walk me through this", "walk me through the",
    "break this down", "break down this",
    "summarize this", "summarise this", "overview of this",
    "tell me about this", "analyse this", "analyze this",
    "review this", "check this", "scan this", "audit this",
    "what is in this", "what is in the", "what's in this",
    "show me what", "show me the issues",
    # Scan intent
    "scan for", "find issues", "find bugs", "find problems", "find vulnerabilities",
    "check for secrets", "check for hardcoded", "check for issues",
    "any issues", "any problems", "any vulnerabilities", "any secrets",
    "are there any", "is there any", "is anything",
    "what issues", "what problems", "what vulnerabilities",
    # Security intent
    "is this secure", "is it secure", "is the config secure",
    "exposed secret", "leaked",
    "security issue", "security issues", "security problem",
    # Implicit file questions
    "what ports are exposed", "what port is", "which port",
    "what images are", "which image is", "what version is being used",
    "what environment variables", "what secrets are", "what resources",
    "is the pipeline", "does the pipeline", "how is the pipeline",
    "does this follow", "does it follow", "is this following",
    "what is configured", "how is this configured", "how is it configured",
    "are there any issues", "are there problems",
    # Advanced analysis triggers
    "risk score", "security score", "threat narrative",
    "compliance mapping", "cwe mapping", "owasp mapping",
    "dependency map", "dependency relationship", "infrastructure map",
    "exploitability", "attack chain", "blast radius",
    "generate fix", "generate fixes", "fix all", "remediate",
    "patch this", "harden this", "harden the",
    "threat model", "attack surface", "attack path",
    "false positive", "mark as accepted", "accepted risk",
]

# =========================================================
# GENERAL MODE STARTERS
# =========================================================
GENERAL_MODE_STARTERS = [
    "what is devops", "what is devsecops", "what is sre",
    "what is kubernetes", "what is docker", "what is helm",
    "what is terraform", "what is ansible", "what is jenkins",
    "what is argocd", "what is gitops", "what is ci/cd",
    "what is a service mesh", "what is istio", "what is linkerd",
    "what is prometheus", "what is grafana", "what is vault",
    "what is a dockerfile", "what is a helm chart",
    "what is infrastructure as code", "what is iac",
    "what is shift left", "what is the 12 factor",
    "what is twelve factor", "what is a monorepo",
    "what is a polyrepo", "what is canary deployment",
    "what is blue green", "what is a service account",
    "what is rbac", "what is a namespace", "what is a pod",
    "what is a node", "what is a container",
    "what is containerization", "what is observability",
    "what is monitoring", "what is tracing", "what is logging",
    "what is slos", "what is slas", "what is slis",
    "what is on call", "what is incident management",
    "what is shift left security", "what is zero trust",
    "what is sbom", "what is supply chain security",
    "what is cwe", "what is owasp", "what is nist",
    "what is mitre", "what is cis benchmark",
    "what is sarif", "what is sast", "what is dast",
    "what is a service account", "what is workload identity",
    "what is opa", "what is gatekeeper", "what is falco",
    "what is cosign", "what is slsa", "what is sigstore",
    "what is renovate", "what is dependabot",
    "explain devops", "explain kubernetes", "explain docker",
    "explain terraform", "explain helm", "explain ci/cd",
    "explain gitops", "explain argocd", "explain jenkins",
    "explain the concept", "explain what devops",
    "explain owasp", "explain cwe", "explain mitre",
    "explain zero trust", "explain shift left",
    "how does kubernetes work", "how does docker work",
    "how does terraform work", "how does helm work",
    "how does ci/cd work", "how does argocd work",
    "how does a container work", "how does a pod work",
    "difference between docker and", "difference between kubernetes and",
    "difference between terraform and", "difference between helm and",
    "difference between ci and cd", "difference between devops and",
    "difference between sast and dast",
    "compare docker and", "compare kubernetes and",
    "pros and cons of docker", "pros and cons of kubernetes",
    "pros and cons of terraform", "pros and cons of ansible",
    "advantages of docker", "advantages of kubernetes",
    "disadvantages of docker", "disadvantages of kubernetes",
    "best practices for ci/cd", "best practices for kubernetes",
    "best practices for docker", "best practices for terraform",
    "best practices for security", "best practices for devops",
    "recommend a tool for", "recommend a monitoring tool",
    "which tool should i use", "what tool should i use",
    "how to write a dockerfile", "how to create a helm chart",
    "how to set up kubernetes", "how to install terraform",
    "how to configure jenkins", "how to use argocd",
    "introduction to devops", "introduction to kubernetes",
    "overview of devops", "overview of kubernetes",
    "tutorial on docker", "tutorial on kubernetes",
    "give me an example of a dockerfile",
    "give me an example of a helm chart",
    "give me an example of a pipeline",
    "give me an example of a terraform",
    "what are microservices", "what are containers",
    "what are namespaces", "what are pods",
    
    "ci vs cd", "ci vs. cd", "ci/cd vs",
    "docker vs podman", "docker vs vm",
    "kubernetes vs docker", "kubernetes vs nomad",
    "terraform vs pulumi", "terraform vs ansible",
    "terraform vs cloudformation",
    "helm vs kustomize",
    "prometheus vs datadog", "prometheus vs grafana",
    "jenkins vs github actions", "jenkins vs gitlab",
    "argocd vs flux", "gitops vs devops",
    "docker vs kubernetes",
    "ansible vs terraform", "ansible vs puppet",
    "vault vs sops", "vault vs aws secrets",
    "trivy vs snyk", "grype vs trivy",
    "istio vs linkerd", "nginx vs traefik",

    # "what's the difference" patterns
    "what's the difference between",
    "whats the difference between",
    "what is the difference between",
    "difference between ci and cd",
    "difference between ci/cd and",
    "difference between docker and",
    "difference between kubernetes and",
    "difference between terraform and",
    "difference between devops and devsecops",
    "difference between helm and kustomize",
    "difference between gitops and devops",

    # "how does X work" — conceptual
    "how does ci work", "how does cd work",
    "how does ci/cd work",
]

# =========================================================
# ROUTING — GENERAL vs FILE MODE
# =========================================================
def is_general_question(user_message: str) -> bool:
    """
    Priority order:
    1. Hard file triggers present          → FILE MODE
    2. No files uploaded                   → GENERAL MODE
    3. Short msg + proximal word + files   → FILE MODE
    4. Pure general knowledge starter      → GENERAL MODE
    5. General pattern without file refs   → GENERAL MODE
    6. Files uploaded + unclassified       → FILE MODE (safe default)
    7. No files + unclassified             → GENERAL MODE
    """
    msg = user_message.lower().strip()
    
def is_general_question(user_message: str) -> bool:
    msg = user_message.lower().strip().rstrip("?! ")
    print(f"[ROUTING] suffix_match={_matches_knowledge_suffix(msg)}")
    # ── INLINE KNOWLEDGE CHECK ────────────────────────────
    # Runs FIRST. No dependency on external function.
    # These are patterns that are ALWAYS general knowledge
    # regardless of whether files are uploaded.

    _file_refs = [
        "this file", "the file", "these files",
        "this repo", "the repo", "this repository",
        "this project", "the project",
        "this code", "the code",
        "this config", "the config",
        "this pipeline", "the pipeline",
        "this dockerfile", "the dockerfile",
        "this terraform", "the terraform",
        "this chart", "the chart",
        "this manifest", "the manifest",
        "uploaded", "my file", "my repo",
        "my code", "my config",
    ]

    _has_file_ref = any(ref in msg for ref in _file_refs)

    if not _has_file_ref:

        # Ends with knowledge signal
        _knowledge_ends = (
            " explained", " best practices", " overview",
            " tutorial", " guide", " concepts", " fundamentals",
            " basics", " cheatsheet", " exam", " certification",
            " interview", " interview questions", " architecture",
            " patterns", " strategies", " roadmap", " networking",
        )
        if any(msg.endswith(s) for s in _knowledge_ends):
            return True

        # Starts with knowledge signal
        _knowledge_starts = (
            "what is ", "what are ", "what was ", "what were ",
            "what's the ", "whats the ",
            "how does ", "how do ", "how can ", "how should ",
            "how to ",
            "explain ", "describe ", "define ",
            "tell me about ", "tell me how ",
            "help me understand ", "help me learn ",
            "help me prepare ", "help me study ",
            "help me pass ", "help me get ready ",
            "i want to learn ", "i want to understand ",
            "i need to learn ", "i need to understand ",
            "teach me ", "show me how ",
            "can you explain ", "can you describe ",
            "can you help me understand ",
            "could you explain ", "could you describe ",
            "please explain ", "please describe ",
            "compare ", "comparing ",
            "difference between ", "differences between ",
            "pros and cons", "advantages of ", "disadvantages of ",
            "when should i use ", "when to use ",
            "why use ", "why is ", "why does ", "why are ",
            "give me an example ", "give an example ",
            "introduction to ", "intro to ",
            "overview of ", "summary of ",
            "tutorial on ", "guide to ", "guide for ",
            "best practices for ", "best practices of ",
            "recommend ", "which tool ", "what tool ",
            "prepare for ", "preparing for ", "study for ",
        )
        if any(msg.startswith(s) for s in _knowledge_starts):
            return True

        # X vs Y pattern
        if " vs " in msg or " vs. " in msg or " versus " in msg:
            return True

        # "X and Y explained" anywhere
        if msg.endswith(" explained"):
            return True

    # ── HARD FILE TRIGGERS ────────────────────────────────
    for trigger in FILE_MODE_HARD_TRIGGERS:
        if trigger in msg:
            return False

    # ── NO FILES ──────────────────────────────────────────
    if len(memory["files"]) == 0:
        return True

    # ── SHORT + PROXIMAL WORDS ────────────────────────────
    words = msg.split()
    proximal_words = {
        "it", "its", "this", "these", "the", "here",
        "above", "attached", "uploaded", "given", "provided"
    }
    if len(words) <= 8:
        for word in words:
            if word in proximal_words:
                return False

    # ── GENERAL MODE STARTERS ─────────────────────────────
    for starter in GENERAL_MODE_STARTERS:
        if msg.startswith(starter) or msg == starter:
            return True

    # ── VS PATTERN (dynamic) ──────────────────────────────
    vs_pattern = re.compile(
        r'^[\w\s\./\-\(\)]+\s+vs\.?\s+[\w\s\./\-\(\)]+$',
        re.IGNORECASE
    )
    if vs_pattern.match(msg.strip()) and len(msg.split()) <= 10:
        return True

    if any(msg.startswith(p) for p in [
        "what's the difference", "whats the difference",
        "what is the difference", "difference between",
    ]):
        return True

    # ── GENERAL PATTERNS ──────────────────────────────────
    general_patterns = [
        "what is ", "what are ", "how does ", "how do ",
        "explain ", "describe ", "define ", "tell me about ",
        "difference between ", "compare ", "pros and cons",
        "advantages of ", "disadvantages of ", "best practice",
        "recommend ", "introduction to ", "overview of ",
        "tutorial ", "give me an example of ",
    ]
    file_ref_words = {
        "this", "these", "the file", "the repo", "the project",
        "uploaded", "my file", "my repo", "the code", "the config",
        "the pipeline", "the dockerfile", "the terraform",
    }
    for pattern in general_patterns:
        if msg.startswith(pattern):
            if not any(ref in msg for ref in file_ref_words):
                return True

    # ── DEFAULT ───────────────────────────────────────────
    if len(memory["files"]) > 0:
        return False
    return True

    # PRIORITY 1
    for trigger in FILE_MODE_HARD_TRIGGERS:
        if trigger in msg:
            return False

    # PRIORITY 2
    if len(memory["files"]) == 0:
        return True

    # PRIORITY 3
    words = msg.split()
    proximal_words = {
        "it", "its", "this", "these", "the", "here",
        "above", "attached", "uploaded", "given", "provided"
    }
    if len(words) <= 8:
        for word in words:
            if word in proximal_words:
                return False

    # PRIORITY 4
    for starter in GENERAL_MODE_STARTERS:
        if msg.startswith(starter) or msg == starter:
            return True
        
    import re as _re
    vs_pattern = _re.compile(
    r'^[\w\s\./]+\s+vs\.?\s+[\w\s\./]+$',
    _re.IGNORECASE
    )
    if vs_pattern.match(msg.strip()) and len(msg.split()) <= 8:
        return True
    
    # Also catch "what's the difference between X and Y"
    if any(msg.startswith(p) for p in [
        "what's the difference", "whats the difference",
        "what is the difference", "difference between",
    ]):
      return True

    # PRIORITY 5
    general_patterns = [
        "what is ", "what are ", "how does ", "how do ",
        "explain ", "describe ", "define ", "tell me about ",
        "difference between ", "compare ", "pros and cons",
        "advantages of ", "disadvantages of ", "best practice",
        "recommend ", "introduction to ", "overview of ",
        "tutorial ", "give me an example of ",
    ]
    file_ref_words = {
        "this", "these", "the file", "the repo", "the project",
        "uploaded", "my file", "my repo", "the code", "the config",
        "the pipeline", "the dockerfile", "the terraform",
    }
    for pattern in general_patterns:
        if msg.startswith(pattern):
            if not any(ref in msg for ref in file_ref_words):
                return True

    # PRIORITY 6/7
    if len(memory["files"]) > 0:
        return False
    return True


# =========================================================
# STACK DETECTION
# =========================================================
def detect_stack(files: list) -> dict:
    """
    Detect technology stack from uploaded file names.
    Used to surface stack context in prompts and adapt analysis mode.
    """
    stack = {
        "iac": [],
        "containers": [],
        "orchestration": [],
        "cicd": [],
        "languages": [],
        "databases": [],
        "monitoring": [],
        "security_tools": [],
    }

    for f in files:
        name = f.get("name", "").lower()

        # IaC
        if name.endswith(".tf") or name.endswith(".tfvars") or "terraform" in name:
            if "Terraform" not in stack["iac"]:
                stack["iac"].append("Terraform")
        if "ansible" in name or name.endswith(".yml") and "playbook" in name:
            if "Ansible" not in stack["iac"]:
                stack["iac"].append("Ansible")
        if "cloudformation" in name or name.endswith(".template"):
            if "CloudFormation" not in stack["iac"]:
                stack["iac"].append("CloudFormation")
        if "pulumi" in name:
            if "Pulumi" not in stack["iac"]:
                stack["iac"].append("Pulumi")

        # Containers
        if "dockerfile" in name:
            if "Docker" not in stack["containers"]:
                stack["containers"].append("Docker")
        if "docker-compose" in name:
            if "Docker Compose" not in stack["containers"]:
                stack["containers"].append("Docker Compose")

        # Orchestration
        if name.endswith(".yaml") or name.endswith(".yml"):
            if any(k in name for k in ["deploy", "service", "ingress", "pod", "stateful", "daemonset", "job", "cronjob", "configmap", "secret", "hpa", "pvc"]):
                if "Kubernetes" not in stack["orchestration"]:
                    stack["orchestration"].append("Kubernetes")
            if "chart" in name or "helm" in name or "values" in name:
                if "Helm" not in stack["orchestration"]:
                    stack["orchestration"].append("Helm")

        # CI/CD
        if ".github" in name or "workflow" in name or "actions" in name:
            if "GitHub Actions" not in stack["cicd"]:
                stack["cicd"].append("GitHub Actions")
        if "gitlab-ci" in name or ".gitlab" in name:
            if "GitLab CI" not in stack["cicd"]:
                stack["cicd"].append("GitLab CI")
        if "jenkinsfile" in name or "jenkins" in name:
            if "Jenkins" not in stack["cicd"]:
                stack["cicd"].append("Jenkins")
        if "circleci" in name or ".circleci" in name:
            if "CircleCI" not in stack["cicd"]:
                stack["cicd"].append("CircleCI")
        if "drone" in name:
            if "Drone CI" not in stack["cicd"]:
                stack["cicd"].append("Drone CI")

        # Languages / build
        if "pom.xml" in name:
            if "Java (Maven)" not in stack["languages"]:
                stack["languages"].append("Java (Maven)")
        if "build.gradle" in name:
            if "Java (Gradle)" not in stack["languages"]:
                stack["languages"].append("Java (Gradle)")
        if name.endswith(".py") or "requirements.txt" in name or "pipfile" in name:
            if "Python" not in stack["languages"]:
                stack["languages"].append("Python")
        if name.endswith(".go") or "go.mod" in name:
            if "Go" not in stack["languages"]:
                stack["languages"].append("Go")
        if name.endswith(".js") or name.endswith(".ts") or "package.json" in name:
            if "Node.js" not in stack["languages"]:
                stack["languages"].append("Node.js")

        # Databases
        if "postgres" in name or "postgresql" in name:
            if "PostgreSQL" not in stack["databases"]:
                stack["databases"].append("PostgreSQL")
        if "mysql" in name:
            if "MySQL" not in stack["databases"]:
                stack["databases"].append("MySQL")
        if "redis" in name:
            if "Redis" not in stack["databases"]:
                stack["databases"].append("Redis")
        if "mongodb" in name or "mongo" in name:
            if "MongoDB" not in stack["databases"]:
                stack["databases"].append("MongoDB")

        # Monitoring
        if "prometheus" in name:
            if "Prometheus" not in stack["monitoring"]:
                stack["monitoring"].append("Prometheus")
        if "grafana" in name:
            if "Grafana" not in stack["monitoring"]:
                stack["monitoring"].append("Grafana")
        if "datadog" in name:
            if "Datadog" not in stack["monitoring"]:
                stack["monitoring"].append("Datadog")

        # Security tools
        if "trivy" in name:
            if "Trivy" not in stack["security_tools"]:
                stack["security_tools"].append("Trivy")
        if "snyk" in name:
            if "Snyk" not in stack["security_tools"]:
                stack["security_tools"].append("Snyk")
        if "checkov" in name:
            if "Checkov" not in stack["security_tools"]:
                stack["security_tools"].append("Checkov")
        if "tfsec" in name:
            if "tfsec" not in stack["security_tools"]:
                stack["security_tools"].append("tfsec")
        if "gitleaks" in name:
            if "Gitleaks" not in stack["security_tools"]:
                stack["security_tools"].append("Gitleaks")
        if "sonar" in name:
            if "SonarQube" not in stack["security_tools"]:
                stack["security_tools"].append("SonarQube")

    return stack


def format_stack_summary(stack: dict) -> str:
    lines = []
    if stack["iac"]:
        lines.append(f"IaC: {', '.join(stack['iac'])}")
    if stack["containers"]:
        lines.append(f"Containers: {', '.join(stack['containers'])}")
    if stack["orchestration"]:
        lines.append(f"Orchestration: {', '.join(stack['orchestration'])}")
    if stack["cicd"]:
        lines.append(f"CI/CD: {', '.join(stack['cicd'])}")
    if stack["languages"]:
        lines.append(f"Languages: {', '.join(stack['languages'])}")
    if stack["databases"]:
        lines.append(f"Databases: {', '.join(stack['databases'])}")
    if stack["monitoring"]:
        lines.append(f"Monitoring: {', '.join(stack['monitoring'])}")
    if stack["security_tools"]:
        lines.append(f"Security Tools: {', '.join(stack['security_tools'])}")
    return "\n".join(lines) if lines else "Stack: General / Unknown"


# =========================================================
# HELPERS
# =========================================================
def get_uploaded_filenames() -> str:
    if not memory["files"]:
        return "No uploaded files"
    return "\n".join([f"- {f['name']}" for f in memory["files"]])


# File context cache — avoids re-reading all files on every
# MODE 3 call. Invalidated when the file list changes.
_file_context_cache: dict = {"key": None, "value": ""}


def _file_cache_key() -> str:
    """Stable cache key based on file names and content lengths."""
    return "|".join(
        f"{f.get('name', '')}:{len(f.get('content', ''))}"
        for f in memory["files"]
    )


def build_full_file_context() -> str:
    global _file_context_cache

    if not memory["files"]:
        return ""

    # Return cached context if files have not changed
    current_key = _file_cache_key()
    if _file_context_cache["key"] == current_key:
        return _file_context_cache["value"]

    blocks = []
    total_chars = 0
    char_limit = 60000

    for f in memory["files"]:
        name = f.get("name", "unknown")
        content = f.get("content", "").strip()
        if not content:
            continue

        block = f"FILE: {name}\n{'-' * 40}\n{content}\n"

        if total_chars + len(block) > char_limit:
            blocks.append(
                f"FILE: {name}\n{'-' * 40}\n"
                f"[File truncated — too large to include in full. "
                f"Ask specifically about this file to analyse it.]\n"
            )
            break

        blocks.append(block)
        total_chars += len(block)

    result = "\n\n".join(blocks)

    # Store in cache
    _file_context_cache["key"] = current_key
    _file_context_cache["value"] = result

    return result


def build_source_list(results: list) -> str:
    if not results:
        return ""
    seen = []
    for item in results:
        source = item.get("source", "unknown")
        if source not in seen:
            seen.append(source)
    return "\n".join([f"- {s}" for s in seen])



# =========================================================
# BUILD PROMPT
# Modes:
# 0.  Off-topic           → polite 2-sentence redirect
# 0.5 Redirect intent     → topic change, sets general_mode
# 0.6 General mode active → stay in general mode until file
#                           trigger explicitly re-engages
# 1.  No files            → general DevOps knowledge
# 2.  Files + general Q   → knowledge, offer file analysis
# 3.  Files + file Q      → full RAG + direct file content
# =========================================================
def build_prompt(user_message: str, history: list) -> str:
    uploaded_files_exist = len(memory["files"]) > 0

    # =====================================================
    # MODE 0.1 — ACKNOWLEDGEMENT / SOCIAL MESSAGE
    # Short one-word or short social responses that should
    # never trigger a full file analysis pass. Respond
    # briefly and conversationally.
    # =====================================================
    if is_acknowledgement(user_message):
        return f"""User Message:
{user_message}

Instructions:

The user sent a brief acknowledgement or social message.
Respond conversationally in 1-2 sentences — friendly and warm.
Do NOT run any file analysis, show security findings, risk scores, or structured cards.
Do NOT reference uploaded files.
If appropriate, invite them to ask their next question or continue the conversation.
"""

    # =====================================================
    # MODE 0 — OFF-TOPIC
    # =====================================================
    if is_off_topic(user_message):
        return f"""User Message:
{user_message}
Instructions:

This question is outside your area of expertise as a DevOps and DevSecOps AI assistant.
Respond with exactly 2-3 sentences maximum.
Sentence 1: Politely acknowledge you cannot help with this specific topic.
Sentence 2: State clearly what you CAN help with — Kubernetes, Docker, Terraform, Helm, CI/CD pipelines, security audits, IaC analysis, DevSecOps.
Sentence 3 (optional): Invite them to upload files or ask a DevOps question.
Do NOT attempt to answer the off-topic question even partially.
Do NOT show repository analysis, findings, dashboard, risk score, or file context.
Do NOT use the file analysis output format.
Tone: friendly and professional, not dismissive.
Example: "That is outside my area — I am a DevOps and DevSecOps AI assistant. I can help with Kubernetes, Docker, Terraform, CI/CD pipelines, security audits, and infrastructure file analysis. Feel free to ask anything in that space or upload files for a full security review."
"""

    # =====================================================
    # MODE 0.5 — REDIRECT INTENT (topic change)
    # Sets general_mode=True so the NEXT messages also
    # stay in general mode — not just this one response.
    # =====================================================
    if is_redirect_intent(user_message):
        memory["general_mode"] = True
        return f"""User Message:
{user_message}

Instructions:

The user wants to change the topic or move away from the current file analysis.
Acknowledge the topic change briefly and warmly in 1-2 sentences.
Invite them to ask their next question — DevOps, security, architecture, or anything in your domain.
Do NOT show any file analysis, repository summary, risk scores, security findings, or structured cards.
Do NOT reference any uploaded files.
Keep it short, conversational, and open-ended.
"""

    # =====================================================
    # MODE 0.6 — GENERAL MODE ACTIVE (post-redirect)
    # The user previously redirected away from file mode.
    # Stay in general mode UNLESS a file hard trigger fires.
    # A file hard trigger resets general_mode back to False.
    # =====================================================
    if memory.get("general_mode") and uploaded_files_exist:
        msg = user_message.lower().strip()
        user_wants_file_analysis = any(trigger in msg for trigger in FILE_MODE_HARD_TRIGGERS)
        if user_wants_file_analysis:
            # User explicitly re-engaged file analysis — exit general mode
            memory["general_mode"] = False
        else:
            # Still in general mode — answer without touching files
            return f"""User Message:
{user_message}

Instructions:

Answer the question directly from your DevOps and DevSecOps expertise.
The user has previously asked to move away from file analysis — do NOT reference uploaded files.
Be direct, technical, and precise.
Use real examples, CLI commands, and code snippets where helpful.
Do NOT show any file analysis, repository summary, risk scores, security findings, or structured cards.
Do NOT reference any uploaded files unless the user explicitly asks about them.
"""

    # =====================================================
    # MODE 1 — NO FILES — PLAIN CHAT MODE
    # =====================================================
    if not uploaded_files_exist:
        memory["general_mode"] = False
        return f"""User Message:
{user_message}

Instructions:

Answer as a senior DevOps and DevSecOps engineer.
Be direct, technical, and precise.
Use real examples, CLI commands, and code snippets where helpful.
If the answer benefits from a code example, always include one.
Do not reference any files since none have been uploaded yet.
If relevant, mention that uploading files enables full security audit with findings, compliance mapping, exploitability scoring, and threat narratives.
"""

    # =====================================================
    # MODE 2 — FILES PRESENT + GENERAL KNOWLEDGE QUESTION
    # =====================================================
    if is_general_question(user_message):
        uploaded_files = get_uploaded_filenames()
        stack = detect_stack(memory["files"])
        stack_summary = format_stack_summary(stack)

        return f"""User Message:
{user_message}

Session Context:
The user has the following files uploaded in this session:
{uploaded_files}

Detected Stack:
{stack_summary}

Instructions:

Answer the question directly from your DevOps and DevSecOps expertise.
Be direct, technical, and precise.
Use real examples, CLI commands, and code snippets where helpful.
Do NOT force file analysis onto this general knowledge question.
Do NOT reference the uploaded files unless they are directly relevant to the answer.
Do NOT show repository summary, findings, dashboard, risk score, or attack surface analysis.
If the detected stack is relevant to the question, you may tailor your answer to that stack.
At the end of your answer, if relevant, offer one line such as:
"I also have your uploaded files ready — let me know if you would like me to run a full security audit."
"""

    # =====================================================
    # MODE 3 — FILES PRESENT + FILE-RELATED QUESTION
    # Full dual-context: direct file injection + RAG
    # File context is cached; RAG results cached per query.
    # =====================================================
    full_file_context = build_full_file_context()

    # RAG cache: skip vector search if same query + same files
    rag_cache_key = f"{user_message.strip().lower()}::{_file_cache_key()}"
    if memory.get("rag_cache_key") == rag_cache_key and memory.get("rag_results"):
        rag_results = memory["rag_results"]
    else:
        rag_results = search(user_message, top_k=5)
        memory["rag_cache_key"] = rag_cache_key
        memory["rag_results"] = rag_results

    rag_context = build_context(rag_results)
    retrieved_sources = build_source_list(rag_results)
    memory["last_topic"] = user_message
    memory["last_files"] = [r.get("source", "") for r in rag_results]
    uploaded_files = get_uploaded_filenames()
    stack = detect_stack(memory["files"])
    stack_summary = format_stack_summary(stack)

    return f"""You have been given the REAL, COMPLETE contents of the uploaded files below.
Analyse them based on their ACTUAL content only.

==========================================================
DETECTED STACK (from uploaded file names):
{stack_summary}
==========================================================
UPLOADED FILES — FULL REAL CONTENT:
{full_file_context}
==========================================================
RAG CONTEXT — MOST RELEVANT CHUNKS FOR THIS QUERY:
{rag_context}
==========================================================
ALL FILES IN THIS SESSION:
{uploaded_files}
==========================================================
USER QUESTION:
{user_message}
==========================================================
INSTRUCTIONS — FOLLOW ALL OF THESE EXACTLY:
ANALYSIS RULES:

Base your ENTIRE answer on the ACTUAL file contents provided above.
ALWAYS cite exact values: version numbers, image names, CIDR blocks, port numbers, resource names, env variable names.
ALWAYS include line numbers: filename:line format — mandatory for every finding.
ALWAYS show the exact code snippet from the file causing the issue.
ALWAYS show the fix as production-ready corrected code — not placeholder text.
For secrets and config changes: use # BAD / # FIX diff format.
Use the detected stack above to adapt analysis focus and recommendations.

REQUIRED PER FINDING (High and Critical):

Risk: precise sentence using actual values
Why it matters: real-world exploitation path — what can an attacker DO
Evidence: filename:line — exact quoted value from the file
Exploitability: HIGH/MEDIUM/LOW with one-sentence reason
Blast Radius: bullet list of affected systems/components/data
Compliance: CWE-XXX | OWASP A0X | CIS X.X | NIST XX-X (only genuinely applicable)
Confidence: [Confidence: HIGH/MEDIUM/LOW] with 2-3 bullet reasons grounded in file evidence
Fix: complete production-ready corrected code block

REQUIRED PER RESPONSE:

Positive Findings section — acknowledge what is correctly configured
Recommendations Summary ordered by Exploitability x Severity
If multiple files: Cross-File Observations for ports, images, secrets, env vars, IAM
If repository zip: include Risk Score, Dependency Relationship Map, Threat Narrative

BANNED BEHAVIOUR:

NEVER say "typically", "usually", "normally", "this file is used for"
NEVER invent CVE IDs unless the file itself contains them
NEVER use placeholder fixes like "replace with your value" — show actual secure values
NEVER invent content not present in the files above
NEVER show repository analysis for off-topic or general knowledge questions
NEVER give repo maturity scores or DevOps maturity assessments unless explicitly asked
If something is not in the files: "This is not defined in the provided files."

FINDING TAGS (required on every finding):
Category: [SECRETS] [MISCONFIGURATION] [VULNERABLE-DEPENDENCY] [DOCKER]
[KUBERNETES] [TERRAFORM] [CI-CD] [COMPLIANCE] [NETWORK]
Confidence: [Confidence: HIGH] [Confidence: MEDIUM] [Confidence: LOW]
Be direct, technical, evidence-based, and precise.
"""