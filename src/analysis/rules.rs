//! Extensible rule system.
//!
//! * Built-in rules ([`builtin_rules`]) and custom rules (config file).
//! * The [`Analyzer`] trait allows plugging other engines (Semgrep/OpenGrep,
//!   CodeQL…) that produce [`Finding`]s in the same format.

use crate::config::CustomRule;
use crate::diff::FileChange;
use anyhow::{bail, Context, Result};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            o => bail!("unknown severity: {o}"),
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
    pub fn lower(self) -> Self {
        match self {
            Self::Critical => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            _ => Self::Info,
        }
    }
    pub const ALL: [Severity; 5] = [Self::Critical, Self::High, Self::Medium, Self::Low, Self::Info];
}

/// Confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            o => bail!("unknown confidence: {o}"),
        })
    }
    pub fn lower(self) -> Self {
        match self {
            Self::High => Self::Medium,
            _ => Self::Low,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Finding category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Authentication,
    Authorization,
    Cryptography,
    InputValidation,
    Configuration,
    Dependencies,
    Secrets,
    Other,
}

impl Category {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "authentication" => Self::Authentication,
            "authorization" => Self::Authorization,
            "cryptography" => Self::Cryptography,
            "input_validation" | "validation" => Self::InputValidation,
            "configuration" => Self::Configuration,
            "dependencies" => Self::Dependencies,
            "secrets" => Self::Secrets,
            "other" => Self::Other,
            o => bail!("unknown category: {o}"),
        })
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Authentication => "Authentication",
            Self::Authorization => "Authorization",
            Self::Cryptography => "Cryptography",
            Self::InputValidation => "Input validation",
            Self::Configuration => "Configuration",
            Self::Dependencies => "Dependencies",
            Self::Secrets => "Secrets",
            Self::Other => "Other",
        }
    }
}

/// Rule trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// Removed (or replaced) line matching the pattern.
    Removed,
    /// Added line matching the pattern.
    Added,
    /// Any change to a file whose path matches.
    FileChanged,
    FileAdded,
    FileDeleted,
}

impl Trigger {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "removed" => Self::Removed,
            "added" => Self::Added,
            "file_changed" => Self::FileChanged,
            "file_added" => Self::FileAdded,
            "file_deleted" => Self::FileDeleted,
            o => bail!("unknown trigger: {o}"),
        })
    }
}

/// Analysis rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub trigger: Trigger,
    pub pattern: Option<Regex>,
    pub path: Option<Regex>,
    pub exclude: Option<Regex>,
    pub justification: String,
    pub builtin: bool,
    /// A single finding per file (with the number of occurrences).
    pub once_per_file: bool,
}

impl Rule {
    pub fn applies_to_path(&self, path: &str) -> bool {
        self.path.as_ref().map(|r| r.is_match(path)).unwrap_or(true)
    }
}

/// Finding (a lead to investigate, not a confirmed vulnerability).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    /// Line in the fork (or in the reference for a removal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<usize>,
    /// removed | added | replaced | modified | file
    pub change: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_code: Option<String>,
    pub justification: String,
    /// Origin: engine that produced the finding (builtin, custom, semgrep…).
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
}

/// Context passed to analyzers.
pub struct AnalysisContext<'a> {
    pub changes: &'a [FileChange],
}

/// Interface of an analysis engine. To integrate Semgrep/OpenGrep or CodeQL,
/// implement this trait (run the tool on the modified files,
/// convert its SARIF/JSON output into `Finding`s) and register it in
/// the pipeline's list of analyzers.
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
}

/// Set of active rules.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Built-in + custom rules, minus disabled rules.
    pub fn load(cfg: &crate::config::SecurityConfig) -> Result<Self> {
        let mut rules: Vec<Rule> = builtin_rules()
            .into_iter()
            .filter(|r| !cfg.disable_rules.contains(&r.id))
            .collect();
        for c in &cfg.rules {
            rules.push(custom_rule(c).with_context(|| format!("custom rule {}", c.id))?);
        }
        Ok(Self { rules })
    }
}

fn custom_rule(c: &CustomRule) -> Result<Rule> {
    let trigger = Trigger::parse(&c.on)?;
    if matches!(trigger, Trigger::Removed | Trigger::Added) && c.pattern.is_none() {
        bail!("`pattern` is required for on = \"{}\"", c.on);
    }
    if matches!(
        trigger,
        Trigger::FileChanged | Trigger::FileAdded | Trigger::FileDeleted
    ) && c.path.is_none()
    {
        bail!("`path` is required for on = \"{}\"", c.on);
    }
    Ok(Rule {
        id: c.id.clone(),
        title: c.title.clone(),
        category: Category::parse(&c.category)?,
        severity: Severity::parse(&c.severity)?,
        confidence: c
            .confidence
            .as_deref()
            .map(Confidence::parse)
            .transpose()?
            .unwrap_or(Confidence::Medium),
        trigger,
        pattern: c.pattern.as_deref().map(Regex::new).transpose()?,
        path: c.path.as_deref().map(Regex::new).transpose()?,
        exclude: c.exclude.as_deref().map(Regex::new).transpose()?,
        justification: c.justification.clone().unwrap_or_else(|| c.title.clone()),
        builtin: false,
        once_per_file: false,
    })
}

struct Def {
    id: &'static str,
    title: &'static str,
    cat: Category,
    sev: Severity,
    conf: Confidence,
    on: Trigger,
    pattern: Option<&'static str>,
    path: Option<&'static str>,
    exclude: Option<&'static str>,
    why: &'static str,
}

#[allow(clippy::too_many_arguments)]
const fn r(
    id: &'static str,
    title: &'static str,
    cat: Category,
    sev: Severity,
    conf: Confidence,
    on: Trigger,
    pattern: &'static str,
    why: &'static str,
) -> Def {
    Def {
        id,
        title,
        cat,
        sev,
        conf,
        on,
        pattern: Some(pattern),
        path: None,
        exclude: None,
        why,
    }
}

const fn p(
    id: &'static str,
    title: &'static str,
    cat: Category,
    sev: Severity,
    on: Trigger,
    path: &'static str,
    why: &'static str,
) -> Def {
    Def {
        id,
        title,
        cat,
        sev,
        conf: Confidence::Medium,
        on,
        pattern: None,
        path: Some(path),
        exclude: None,
        why,
    }
}

use Category::*;
use Confidence as C;
use Severity as S;
use Trigger as T;

const CI_PATHS: &str = r"(^|/)(\.github/workflows/|\.gitlab-ci\.ya?ml$|\.gitlab/|Jenkinsfile|\.circleci/|azure-pipelines\.ya?ml$|\.travis\.yml$|bitbucket-pipelines\.yml$|\.drone\.yml$|\.buildkite/|cloudbuild\.ya?ml$|\.woodpecker)";
const SENSITIVE_NAME: &str = r"(?i)(auth|security|permission|polic(y|ies)|guard|middleware|acl|rbac|csrf|validat|saniti[sz]|crypto|tls|ssl|cert|login|session|jwt|oauth|saml|firewall|access)";

fn defs() -> Vec<Def> {
    vec![
        // ---------------- Authentication ----------------
        r("AUTH-001", "Password check removed or modified", Authentication, S::High, C::Medium, T::Removed,
          r"(?i)(check_?password|verify_?password|password_verify|password_needs_rehash|bcrypt\.(compare|check)|checkpw|compare_?hash|argon2[\w.]*verify|passwordEncoder\.matches|PasswordHasher|validate_?credentials|\bauthenticate\s*\()",
          "An identity check (password/credentials) was removed or modified: risk of authentication bypass."),
        r("AUTH-002", "Weak password hashing", Authentication, S::High, C::Medium, T::Added,
          r"(?i)(passw(or)?d|pwd).{0,40}\b(md5|sha1|sha-1|crc32|base64)\b|\b(md5|sha1)\b.{0,40}(passw(or)?d|pwd)",
          "An algorithm unsuitable for password storage seems to be used."),
        r("AUTH-003", "Authentication check removed", Authentication, S::High, C::Medium, T::Removed,
          r"(?i)(@login_required|@authenticated|@jwt_required|@auth\.|\bis_?authenticated\b|\brequire_?auth\b|\bauthMiddleware\b|ensureAuthenticated|passport\.authenticate|\[Authorize|@PreAuthorize|@Secured|before_action\s*:authenticate|authenticate_user!|auth:sanctum|middleware\(\s*['\x22]auth|IsAuthenticated|requireLogin|checkAuth|verifySession|@UseGuards)",
          "An authentication decorator/middleware was removed: routes may have become public."),
        r("AUTH-004", "Authentication bypass added", Authentication, S::High, C::Medium, T::Added,
          r"(?i)(\[AllowAnonymous\]|@AllowAnonymous|permitAll\(\)|@PermitAll|skip_before_action\s*:authenticate|authentication_classes\s*=\s*\[\s*\]|permission_classes\s*=\s*\[\s*(AllowAny)?\s*\]|\bAllowAny\b|auth\s*[:=]\s*(false|False|None)\b|@Public\(\)|isPublic\s*[:=]\s*true|anonymous\s*[:=]\s*true)",
          "A route or component is explicitly exempted from authentication."),
        r("AUTH-005", "JWT validation disabled or weakened", Authentication, S::Critical, C::High, T::Added,
          r"(?i)(algorithms?['\x22]?\s*[=:]\s*(\[[^\]]*)?['\x22]none['\x22]|alg['\x22]?\s*[=:]\s*['\x22]none['\x22]|verify_signature['\x22]?\s*[:=]\s*False|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|verify_exp['\x22]?\s*[:=]\s*False|validate_exp\s*=\s*false|ValidateLifetime\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false|insecure_disable_signature_validation|dangerous_insecure_decode|\.decode\(\s*[^,]+,\s*options\s*=\s*\{[^}]*verify)",
          "JWT signature or expiry verification seems disabled."),
        r("AUTH-006", "JWT verification removed or modified", Authentication, S::High, C::Medium, T::Removed,
          r"(?i)(jwt\.verify|jwt\.decode|verify_?jwt|verifyToken|validate_?token|JwtBearer|ValidateIssuer|ValidateAudience|ValidateLifetime|jsonwebtoken::decode|Validation::new|decode_?token|algorithms\s*=)",
          "The token validation mechanism was modified: check signature, algorithm, audience and expiry."),
        r("AUTH-007", "Insecure session cookie", Authentication, S::Medium, C::Medium, T::Added,
          r"(?i)((SESSION|CSRF)_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|httpOnly\s*:\s*false|\bsecure\s*:\s*false|SameSite\s*=\s*None|sameSite\s*:\s*['\x22]none|cookie_secure\s*=\s*(false|0)|session\.cookie_(secure|httponly)\s*=\s*(0|off|false))",
          "Security attributes of session cookies were weakened."),
        r("AUTH-008", "Session settings modified", Authentication, S::Low, C::Low, T::Removed,
          r"(?i)(maxAge|max_age|SESSION_COOKIE_AGE|session\.timeout|session_timeout|expire_after|PERMANENT_SESSION_LIFETIME|session\.gc_maxlifetime|regenerate(_id)?\()",
          "Session lifetime or regeneration was modified."),
        r("AUTH-009", "Comparison with a hard-coded value (potential backdoor)", Authentication, S::Critical, C::Medium, T::Added,
          r"(?i)((passw(or)?d|passwd|pwd|token|api_?key|secret|username|user)\s*(==|===|\.equals\()\s*['\x22][^'\x22]{3,}['\x22]|['\x22][^'\x22]{3,}['\x22]\s*(==|===)\s*(passw(or)?d|token|api_?key|secret)\b|\b(master_?password|backdoor|god_?mode|skip_?auth|bypass_?auth)\b)",
          "Authentication seems to compare an input with a fixed value: possible backdoor."),
        r("AUTH-010", "Rate limiting / anti-bruteforce removed", Authentication, S::Medium, C::Medium, T::Removed,
          r"(?i)(rate_?limit|RateLimit|throttl|\blimiter\b|express-rate-limit|slowDown|max_?login_?attempts|lockout|failed_?attempts)",
          "A protection against brute force or abuse was removed."),
        r("AUTH-011", "Neutralised control condition", Authentication, S::High, C::Medium, T::Added,
          r"(?i)(\bif\s*\(?\s*(false|0)\s*(and\b|&&)|(\bor\b|\|\|)\s*(true|1)\s*\)?\s*(:|\{|then\b)|\bif\s*\(?\s*(true|false|1|0)\s*\)?\s*(:|\{|then\b)|\breturn\s+(true|True)\s*;?\s*(#|//)\s*(todo|fixme|hack|temp|bypass))",
          "A condition was made constant (if False and …, or True…): a check may have been disabled."),
        // ---------------- Authorization ----------------
        r("AUTHZ-001", "Role / permission check removed or modified", Authorization, S::High, C::Medium, T::Removed,
          r"(?i)(\bis_?admin\b|\bisAdmin\b|is_superuser|is_staff|has_?role|hasAnyRole|hasAuthority|has_perm|has_?permission|hasPermission|\bcan\?\(|authorize[!(]|\.can\(|@RolesAllowed|check_?permission|require_?role|requireRole|ensure_?role|abort_unless|Gate::|\$this->authorize|policy\(|\bpermissions?\.(check|has)|\.role\s*(==|!=|===|!==|in\b)|role\s*(==|!=|===|!==)\s*['\x22])",
          "A role/permission-based access control was removed or modified."),
        r("AUTHZ-002", "Privilege escalation or broad permissions", Authorization, S::High, C::Medium, T::Added,
          r"(?i)(role\s*[=:]\s*['\x22](admin|root|superuser)['\x22]|is_?admin\s*[=:]\s*(true|True|1)\b|is_superuser\s*=\s*True|grant\s+all|chmod\s+(-R\s+)?(0?777|a\+rwx)|\b0o?777\b|os\.chmod\([^)]*0o?7[67]7)",
          "High privileges seem to be granted by default or overly broad permissions are applied."),
        r("AUTHZ-003", "Resource ownership check removed", Authorization, S::Medium, C::Medium, T::Removed,
          r"(?i)((owner_?id|user_?id|ownerId|userId|created_?by|tenant_?id|tenantId|account_?id)\s*(==|!=|===|!==)|\.owner\s*(==|!=)|current_user\.id|request\.user\.id|req\.user\.id|auth\(\)->id\(\)|belongs_?to)",
          "A check that a resource belongs to the user was removed (IDOR risk)."),
        r("AUTHZ-004", "Access-denied response removed", Authorization, S::Medium, C::Low, T::Removed,
          r"(?i)(\b403\b|Forbidden|PermissionDenied|AccessDenied|\bUnauthorized\b|abort\(\s*40[13]|HttpStatus\.FORBIDDEN|StatusForbidden|NotAuthorized)",
          "A branch returning an access-denied error was removed."),
        // ---------------- Cryptography ----------------
        r("CRYPTO-001", "TLS / certificate validation disabled", Cryptography, S::Critical, C::High, T::Added,
          r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify\s*:\s*true|danger_accept_invalid_(certs|hostnames)\s*\(\s*true|CERT_NONE|check_hostname\s*=\s*False|ssl_?verify\s*[=:]\s*(false|0|False)|SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)|curl\b.*\s(-k|--insecure)\b|strict-ssl\s*[=:]?\s*false|sslmode=disable|TrustAll|trustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|ServerCertificateValidationCallback\s*=|VERIFY_NONE|tls_insecure|insecure_skip_tls_verify|\binsecure\s*[:=]\s*true|GIT_SSL_NO_VERIFY|http\.sslVerify\s*false)",
          "TLS certificate verification seems disabled: interception (MITM) possible."),
        r("CRYPTO-002", "Certificate verification removed", Cryptography, S::High, C::Medium, T::Removed,
          r"(?i)(verify\s*=\s*True|rejectUnauthorized\s*:\s*true|CERT_REQUIRED|check_hostname\s*=\s*True|verify_?peer|VerifyPeer|load_verify_locations|set_verify|verify_cert|VERIFY_PEER|\bcafile\b|ca_certs|RootCAs|add_root_certificate|VerifyHostname|hostname_?verif|pinning|certificatePinner)",
          "A certificate verification (or pinning) mechanism was removed."),
        r("CRYPTO-003", "Weak cryptographic algorithm or insecure randomness", Cryptography, S::Medium, C::Medium, T::Added,
          r"(?i)(\b(md5|sha1|rc4|des|3des|tripledes|blowfish)\b\s*\(|hashlib\.(md5|sha1)|MessageDigest\.getInstance\(\s*['\x22](MD5|SHA-?1)|Cipher\.getInstance\(\s*['\x22](DES|AES['\x22]|AES/ECB|RC4)|\bAES-?\d*-?ECB\b|createCipher\(|\bMODE_ECB\b|PKCS1v15|Math\.random\(|\brand\(\)|mt_rand\(|random\.random\(|new Random\()",
          "An obsolete cryptographic algorithm or a non-cryptographic random generator is used."),
        r("CRYPTO-004", "Strong cryptographic primitive removed or replaced", Cryptography, S::Medium, C::Low, T::Removed,
          r"(?i)(sha-?256|sha-?512|aes-?256|aes-gcm|\bGCM\b|argon2|bcrypt|scrypt|pbkdf2|\bRS256\b|\bES256\b|\bHS512\b|chacha20|ed25519|secrets\.(token|choice)|crypto\.randomBytes|SecureRandom|OsRng|getrandom|random_bytes\()",
          "A strong cryptographic algorithm or generator was removed or replaced."),
        Def {
            id: "CRYPTO-005", title: "Hard-coded cryptographic key", cat: Cryptography, sev: S::High, conf: C::Medium, on: T::Added,
            pattern: Some(r"(?i)\b(secret_?key|private_?key|encryption_?key|signing_?key|jwt_?secret|aes_?key|hmac_?key|app_?key|cipher_?key)\b\s*[:=]\s*['\x22][^'\x22\s$%{}<>]{8,}['\x22]"),
            path: None,
            exclude: Some(r"(?i)(getenv|environ|process\.env|ENV\[|config\(|\$\{)"),
            why: "A cryptographic key seems to be defined directly in the code.",
        },
        r("CRYPTO-006", "Cryptographic cost parameter modified", Cryptography, S::Low, C::Low, T::Added,
          r"(?i)\b(iterations|rounds|cost|work_?factor|saltRounds|log_rounds|key_?size|keysize|bits)\s*[:=]\s*\d+",
          "A strength parameter (iterations, key size) was modified: compare with the original value."),
        // ---------------- Input validation ----------------
        r("INPUT-001", "Input validation or sanitisation removed", InputValidation, S::Medium, C::Medium, T::Removed,
          r"(?i)(validat|saniti[sz]|\bescape|htmlspecialchars|htmlentities|strip_tags|bleach\.|DOMPurify|purify|@Valid\b|@Validated|filter_var|filter_input|Joi\.|yup\.|\bz\.(object|string|number)|safeParse|is_valid\(|isValid\(|ValidationError|whitelist|allowlist|allowed_(chars|values)|re\.(match|fullmatch)\()",
          "Input validation or sanitisation was removed or modified."),
        r("INPUT-002", "Input validation added", InputValidation, S::Info, C::Low, T::Added,
          r"(?i)(validat|saniti[sz]|htmlspecialchars|DOMPurify|@Valid\b|filter_var|Joi\.|yup\.|\bz\.object|safeParse|is_valid\()",
          "A validation was added: check that it is complete and enforced server-side."),
        r("INPUT-003", "SQL query built by concatenation", InputValidation, S::High, C::Medium, T::Added,
          r"(?i)(\b(select|insert\s+into|update|delete\s+from)\b.*\b(from|values|set|where)\b.*(['\x22]\s*\+\s*\w|\+\s*['\x22]|\$\{|%s['\x22]?\s*%|f['\x22]|\.format\(|['\x22]\s*\.\s*\$)|\b(raw|execute|exec_query|rawQuery|createQuery|createNativeQuery|executeQuery|find_by_sql|whereRaw|DB::raw|\.extra)\s*\(\s*(f['\x22]|['\x22][^'\x22]*['\x22]\s*(\+|%|\.)))",
          "An SQL query seems to be built dynamically: risk of SQL injection."),
        r("INPUT-004", "SQL query or parameter binding modified", InputValidation, S::Medium, C::Low, T::Removed,
          r"(?i)(\b(select|insert\s+into|update|delete\s+from)\b.*\b(from|values|set|where)\b|prepareStatement|PreparedStatement|bind_param|bindParam|bindValue|setParameter|parameterized|\$\d+\b.*\[)",
          "An SQL query or a parameterised query mechanism was modified."),
        r("INPUT-005", "XSS protection disabled", InputValidation, S::Medium, C::Medium, T::Added,
          r"(?i)(dangerouslySetInnerHTML|v-html|\|\s*safe\b|mark_safe|autoescape\s+(false|off)|autoescape\s*=\s*False|\{\{\{|<%==|\braw\(|html_safe|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|bypassSecurityTrust|escape\s*[:=]\s*false|Html\.Raw|\$sce\.trustAsHtml|insertAdjacentHTML)",
          "Unescaped HTML rendering was introduced: risk of XSS."),
        r("INPUT-006", "CSRF protection disabled", InputValidation, S::High, C::High, T::Added,
          r"(?i)(@?csrf_exempt|csrf\(\)\.disable|csrf\.disable|\.csrf\(\s*\w*\s*->\s*\w*\.disable|(WTF_)?CSRF_ENABLED\s*=\s*False|protect_from_forgery\s+.*null_session|skip_before_action\s*:verify_authenticity_token|skip_forgery_protection|csrf\s*:\s*false|ignoringAntMatchers|ignoringRequestMatchers|IgnoreAntiforgeryToken)",
          "CSRF protection was disabled for all or part of the application."),
        r("INPUT-007", "CSRF protection removed", InputValidation, S::High, C::Medium, T::Removed,
          r"(?i)(csrf|CsrfViewMiddleware|protect_from_forgery|csurf|csrfProtection|verify_authenticity_token|AntiForgery|ValidateAntiForgeryToken|xsrf)",
          "A CSRF protection element was removed."),
        Def {
            id: "INPUT-008", title: "Code / command execution or dangerous deserialisation", cat: InputValidation, sev: S::High, conf: C::Medium, on: T::Added,
            pattern: Some(r"(?i)(\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|shell_exec|passthru|\bpopen\(|shell\s*=\s*True|os\.system|Runtime\.getRuntime\(\)\.exec|child_process|execSync|spawn\([^)]*shell\s*:\s*true|pickle\.loads?|yaml\.load\(|unserialize\(|Marshal\.load|ObjectInputStream|BinaryFormatter|new Function\(|vm\.runIn|Command::new\()"),
            path: None,
            exclude: Some(r"(?i)(SafeLoader|safe_load|yaml\.load\([^)]*Loader\s*=\s*yaml\.SafeLoader)"),
            why: "A command or expression execution, or an unsafe deserialisation, was added.",
        },
        r("INPUT-009", "Path traversal / upload protection removed", InputValidation, S::Low, C::Low, T::Removed,
          r"(?i)(secure_filename|basename\(|realpath|canonicaliz|path\.normalize|path\.resolve|\.\./|allowed_extensions|ALLOWED_EXTENSIONS|mimetype|content_type|max_content_length|MAX_UPLOAD|startsWith\(\s*(base|root))",
          "A check on paths or uploaded files was removed."),
        Def {
            id: "INPUT-010", title: "Request to a controllable URL (potential SSRF)", cat: InputValidation, sev: S::Low, conf: C::Low, on: T::Added,
            pattern: Some(r"(?i)(requests\.(get|post)|urlopen|fetch|axios\.(get|post)|http\.Get|reqwest::get|HttpClient|curl_exec|file_get_contents)\s*\(\s*[^'\x22\s)]"),
            path: None, exclude: None,
            why: "An outgoing request uses a dynamic URL: check that it is not user-controlled.",
        },
        // ---------------- Configuration ----------------
        r("CONF-001", "CORS permissif", Configuration, S::Medium, C::Medium, T::Added,
          r"(?i)(Access-Control-Allow-Origin['\x22]?\s*[,:=]\s*['\x22]\*|\borigins?\s*[:=]\s*\[?\s*['\x22]\*|origin\s*:\s*true|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*['\x22]\*|AllowAnyOrigin|allowedOrigins?\(\s*['\x22]\*|allowed_origins.*\*|Access-Control-Allow-Credentials['\x22]?\s*[,:=]\s*['\x22]?true|credentials\s*:\s*true|\bcors\(\s*\))",
          "The CORS policy seems to allow every origin (or credentials)."),
        r("CONF-002", "CORS configuration modified", Configuration, S::Low, C::Low, T::Removed,
          r"(?i)(cors|Access-Control-Allow|allowed_?origins|allowOrigin)",
          "The CORS configuration was modified."),
        r("CONF-003", "Service exposure or debug mode", Configuration, S::Medium, C::Medium, T::Added,
          r"(?i)(0\.0\.0\.0|\bhost\s*[:=]\s*['\x22]?::['\x22]?|^\s*EXPOSE\s+\d+|--publish|-p\s+\d+:\d+|network_mode:\s*['\x22]?host|hostNetwork:\s*true|type:\s*(LoadBalancer|NodePort)|\bDEBUG\s*=\s*(True|1|true)|debug\s*[:=]\s*true|APP_DEBUG\s*=\s*true|FLASK_DEBUG\s*=\s*1|app\.run\([^)]*debug\s*=\s*True|exposure\.include\s*[=:]\s*['\x22]?\*|enable_?swagger|graphiql\s*[:=]\s*true|introspection\s*[:=]\s*true)",
          "A service is exposed on all interfaces or a debug mode is enabled."),
        r("CONF-004", "Extended container permissions", Configuration, S::High, C::High, T::Added,
          r"(?i)(privileged\s*:\s*true|--privileged|cap_add|CAP_SYS_ADMIN|SYS_PTRACE|NET_ADMIN|allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b|runAsNonRoot:\s*false|^\s*USER\s+(root|0)\b|/var/run/docker\.sock|hostPID:\s*true|hostIPC:\s*true|seccomp[:=]?\s*unconfined|apparmor[:=]?\s*unconfined|readOnlyRootFilesystem:\s*false|pid:\s*['\x22]?host)",
          "The container gets extended privileges or host access."),
        r("CONF-005", "Container hardening removed", Configuration, S::Medium, C::Medium, T::Removed,
          r"(?i)(^\s*USER\s+\w+|runAsNonRoot:\s*true|readOnlyRootFilesystem:\s*true|allowPrivilegeEscalation:\s*false|no-new-privileges|cap_drop|drop:\s*\[?\s*['\x22]?ALL|securityContext)",
          "A container hardening measure was removed."),
        p("CONF-006", "CI/CD workflow modified", Configuration, S::Medium, T::FileChanged, CI_PATHS,
          "CI/CD pipelines run code with access to secrets: every change must be reviewed."),
        Def {
            id: "CONF-007", title: "Dangerous CI/CD construct", cat: Configuration, sev: S::High, conf: C::Medium, on: T::Added,
            pattern: Some(r"(?i)(pull_request_target|workflow_run|permissions:\s*write-all|contents:\s*write|id-token:\s*write|\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit|review|discussion)\.[^}]*(title|body|ref|label|name|message)|curl[^|\n]*\|\s*(sudo\s+)?(ba)?sh|wget[^|\n]*\|\s*(sudo\s+)?(ba)?sh|ACTIONS_ALLOW_UNSECURE_COMMANDS|uses:\s*[\w.-]+/[\w./-]+@(main|master|latest)\b|CI_JOB_TOKEN|DOCKER_AUTH_CONFIG)"),
            path: Some(CI_PATHS), exclude: None,
            why: "Risky CI/CD construct (expression injection, broad permissions, remote script execution, unpinned action).",
        },
        p("CONF-008", "Docker / orchestration file modified", Configuration, S::Low, T::FileChanged,
          r"(?i)(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|\.dockerignore)$|(^|/)(k8s|kubernetes|helm|charts|manifests)/",
          "The containerisation/deployment configuration was modified."),
        p("CONF-009", "Sensitive configuration file modified", Configuration, S::Low, T::FileChanged,
          r"(?i)(^|/)(\.env[^/]*|settings\.py|config/(security|auth|cors|session)[^/]*|security\.ya?ml|application[^/]*\.(properties|ya?ml)|web\.config|nginx[^/]*\.conf|httpd\.conf|\.htaccess|Caddyfile|sshd_config|sudoers|\.npmrc|\.pypirc|pip\.conf|\.yarnrc(\.yml)?|\.cargo/config(\.toml)?|settings\.xml|nuget\.config)$",
          "A configuration file with security impact was modified."),
        r("CONF-010", "Security header or redirect removed", Configuration, S::Medium, C::Medium, T::Removed,
          r"(?i)(helmet|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|\bHSTS\b|X-Content-Type-Options|SECURE_SSL_REDIRECT|SECURE_HSTS|force_ssl|requires_?channel|requiresSecure|UseHsts|UseHttpsRedirection)",
          "An HTTP security header or an HTTPS redirect was removed."),
        r("CONF-011", "Security logging removed", Configuration, S::Low, C::Low, T::Removed,
          r"(?i)(audit_?log|auditLog|security_?log|log(ger)?\.(warn|warning|error|info|critical)\(.*(login|auth|fail|denied|forbidden|attempt))",
          "An audit or security log statement was removed."),
        Def {
            id: "CONF-012", title: "Package source modified", cat: Dependencies, sev: S::Medium, conf: C::Medium, on: T::Added,
            pattern: Some(r"(?i)(--(extra-)?index-url|\bregistry\s*[=:]\s*['\x22]?https?://|@[\w-]+:registry\s*=|\[registries|\[source\.|replace-with\s*=|npmRegistryServer|<repository>|maven\s*\{\s*url|GOPROXY\s*=|GOPRIVATE|GONOSUMDB|GOFLAGS\s*=.*-insecure|^\s*source\s+['\x22]https?://)"),
            path: None,
            exclude: Some(r"(?i)^\s*source\s+['\x22]https://rubygems\.org"),
            why: "A dependency download source was added or modified (risk of dependency confusion / malicious registry).",
        },
        r("OTHER-001", "Git conflict markers", Other, S::Medium, C::High, T::Added,
          r"^(<{7}|>{7})( |$)",
          "Merge conflict markers are present: the code is probably not in a consistent or deployable state."),
        // ---------------- Files ----------------
        p("FILE-001", "Security-related file removed", Other, S::Medium, T::FileDeleted, SENSITIVE_NAME,
          "A file whose name suggests a security mechanism was removed (feature possibly removed)."),
        Def {
            id: "FILE-002", title: "Security-related file modified", cat: Other, sev: S::Info, conf: C::Low, on: T::FileChanged,
            pattern: None, path: Some(SENSITIVE_NAME), exclude: None,
            why: "The file name suggests a security mechanism: review recommended (weak hint based on the name).",
        },
        p("FILE-003", "Binary or compiled artefact added", Other, S::Medium, T::FileAdded,
          r"(?i)\.(exe|dll|so|dylib|jar|war|ear|class|pyc|pyo|bin|elf|apk|dex|o|a|lib|msi|deb|rpm|wasm|node)$",
          "A binary added to the source code cannot be reviewed and may hide malicious code."),
        p("FILE-004", "Tests removed", Other, S::Low, T::FileDeleted,
          r"(?i)(^|/)(tests?|spec|__tests__)/|(_test|\.test|\.spec|_spec)\.[a-z]+$|(^|/)test_[^/]+$",
          "Tests were removed: a feature or protection may have been removed without detection."),
        p("FILE-005", "Install hook or script modified", Configuration, S::Medium, T::FileChanged,
          r"(?i)(^|/)(build\.rs|setup\.py|install\.sh|postinstall[^/]*|preinstall[^/]*|\.husky/|\.githooks/|Makefile|Rakefile|conftest\.py)$",
          "A script run automatically at build/install time was modified."),
    ]
}

/// Built-in rules.
pub fn builtin_rules() -> Vec<Rule> {
    defs()
        .into_iter()
        .map(|d| Rule {
            id: d.id.to_string(),
            title: d.title.to_string(),
            category: d.cat,
            severity: d.sev,
            confidence: d.conf,
            trigger: d.on,
            pattern: d
                .pattern
                .map(|p| Regex::new(p).unwrap_or_else(|e| panic!("invalid rule {}: {e}", d.id))),
            path: d
                .path
                .map(|p| Regex::new(p).unwrap_or_else(|e| panic!("invalid rule {}: {e}", d.id))),
            exclude: d
                .exclude
                .map(|p| Regex::new(p).unwrap_or_else(|e| panic!("invalid rule {}: {e}", d.id))),
            once_per_file: d.id == "OTHER-001",
            justification: d.why.to_string(),
            builtin: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_compile() {
        let rules = builtin_rules();
        assert!(rules.len() > 30);
        let mut ids: Vec<_> = rules.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "unique identifiers");
    }
}
