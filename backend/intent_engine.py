# =========================================================
# INTENT ENGINE
# Single home for message classification. Runs BEFORE any
# prompt building so casual or off-topic messages never
# trigger an LLM call or file analysis.
# =========================================================

import re

# =========================================================
# GREETINGS
# =========================================================

GREETING_PHRASES = {
    "hi", "hello", "hey", "hiya", "howdy", "heya", "heyy", "hihi",
    "good morning", "good afternoon", "good evening", "good day",
    "what's up", "whats up", "wats up", "wat up",
    "wassup", "wazzup", "sup", "yo",
}

# =========================================================
# SMALL TALK
# =========================================================

SMALL_TALK_PHRASES = {
    "how are you", "how are you doing", "how do you do",
    "how r u", "how are u", "hru",
    "how's it going", "hows it going", "how is it going",
    "how are things", "how's everything", "how have you been",
    "what's new", "whats new", "anything new",
    "are you ok", "are you good", "you good", "u good",
    "what are you", "who are you", "tell me about yourself",
    "what can you do", "what do you do",
    "are you an ai", "are you a bot", "are you human",
    "what is your name", "whats your name",
}

# =========================================================
# CLEAR
# =========================================================

CLEAR_PHRASES = {
    "clear", "clear chat", "reset", "start over", "new chat",
    "clear history", "reset chat", "clear context",
}

# =========================================================
# ACKNOWLEDGEMENTS
# Short confirmatory/social replies that should never
# trigger a full file analysis pass.
# =========================================================

ACKNOWLEDGEMENT_PHRASES = {
    # Confirmations
    "ok", "okay", "k", "got it", "got that", "understood",
    "makes sense", "i see", "i understand", "fair enough",
    "fair", "noted", "alright", "alright then",
    # Positive reactions
    "great", "good", "nice", "cool", "awesome", "perfect",
    "excellent", "wonderful", "fantastic", "brilliant",
    "amazing", "superb", "love it", "love that",
    "looks good", "looks great", "sounds good", "sounds great",
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
    # Emoji-only
    "👍", "👌", "✅", "🙏", "😊", "🔥",
}

# Max word count to even attempt acknowledgement check
_ACK_MAX_WORDS = 8

# An explicit analysis command anywhere in the message means it is NOT a
# bare acknowledgement, even when it starts with an ack word. Without this,
# "yes audit" / "sure, scan it" / "go ahead review this" match the "yes" /
# "sure" / "go ahead" ack phrases and get answered with a canned prompt
# instead of running the scan the user just asked for.
_ANALYSIS_TRIGGERS = (
    "audit", "analy", "scan", "review", "inspect", "assess",
    "finding", "secret", "misconfig", "vulnerab", "harden",
    "full report", "security report",
)


def is_acknowledgement(user_message: str) -> bool:
    """
    Returns True if the message is a short social/acknowledgement
    response that should never trigger a full file analysis pass.
    """
    msg = user_message.lower().strip().rstrip("!.,?")
    words = msg.split()

    if len(words) > _ACK_MAX_WORDS:
        return False

    # A message carrying an explicit analysis command is an action request,
    # not an acknowledgement — let it fall through to file analysis.
    if any(trigger in msg for trigger in _ANALYSIS_TRIGGERS):
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
    "renovate", "dependabot", "whitesource",
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

# Tokens like "ci/cd", "cert-manager", "route53" must survive
# tokenisation as single units.
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+(?:[/\.\-][a-z0-9]+)*")


def _contains_term(text: str, terms: set) -> bool:
    """
    Word-boundary matching: multi-word terms match as substrings,
    single-word terms must match a whole token — so "sports" no
    longer matches "port" and "important" no longer matches "port".
    """
    tokens = set(_TOKEN_PATTERN.findall(text))
    for term in terms:
        if " " in term:
            if term in text:
                return True
        elif term in tokens:
            return True
    return False


def is_off_topic(user_message: str) -> bool:
    """
    Returns True if the message is clearly unrelated to DevOps/tech.
    DevOps term presence overrides all other signals.
    """
    msg = user_message.lower().strip().rstrip("?!.,")

    # RULE 1 — Any DevOps term present → never off-topic
    if _contains_term(msg, DEVOPS_TERMS):
        return False

    # RULE 2 — Known off-topic person names
    if _contains_term(msg, OFF_TOPIC_PERSON_NAMES):
        return True

    # RULE 3 — "who is X" / "who was X" with non-DevOps subject
    if msg.startswith("who is ") or msg.startswith("who was "):
        subject = msg.replace("who is ", "").replace("who was ", "").strip()
        if not _contains_term(subject, DEVOPS_TERMS):
            return True

    # RULE 4 — "tell me about X" with no DevOps subject, short phrase
    if msg.startswith("tell me about "):
        subject = msg.replace("tell me about ", "").strip()
        if not _contains_term(subject, DEVOPS_TERMS):
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
        if not has_file_signal:
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
# INTENT DETECTION
# =========================================================

def detect_intent(user_message: str) -> str:
    """
    Returns one of:
      - greeting
      - small_talk
      - clear
      - acknowledgement
      - off_topic
      - chat  (default — send to LLM)
    """
    msg = user_message.lower().strip().rstrip("!.,?")

    if msg in GREETING_PHRASES:
        return "greeting"

    if msg in SMALL_TALK_PHRASES:
        return "small_talk"

    if msg in CLEAR_PHRASES:
        return "clear"

    if is_acknowledgement(user_message):
        return "acknowledgement"

    if is_off_topic(user_message):
        return "off_topic"

    return "chat"
