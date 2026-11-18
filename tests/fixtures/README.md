# Test fixtures

Test Git repositories are **generated on the fly** by `tests/common/mod.rs`
in temporary directories (deterministic dates and identities) instead of
being stored as binaries: this keeps them reproducible and avoids shipping
`.git` directories inside the project.

Reference source repository (`make_upstream`):

| Commit | Tag  | Content |
|--------|------|---------|
| c1     | v1.0 | initial version (auth, views, network, helpers, dependencies) |
| c2     | v1.1 | adds `extra()` (annotated tag) |
| c3     | —    | new feature (`src/feature.py`) |
| c4     | v1.2 | "security: validate URL scheme (CVE-2024-0001)" |

Covered scenarios (`tests/*.rs`):

1. Simple fork with two specific commits — `git_history.rs::simple_fork_two_commits`
2. Fork with several source merges — `git_history.rs::fork_with_multiple_upstream_merges`
3. Rebased fork — `git_history.rs::fork_with_rebase`
4. Fork with cherry-pick — `git_history.rs::fork_with_cherry_pick`
5. Fork with rewritten history — `reference_detection.rs::rewritten_history`
6. Fork sources without Git history — `reference_detection.rs::sources_without_git`
7. Added and deleted files — `diff.rs::added_and_deleted_files`
8. Uncommitted local changes — `git_history.rs::uncommitted_changes`
9. File renames — `diff.rs::renames_without_git_information`
10. Authentication mechanism change — `security.rs::authentication_change_is_flagged`
11. TLS validation removed — `security.rs::tls_validation_removed`
12. Dependency added — `security.rs::dependency_added`
13. Secret added to the code — `security.rs::secret_added_and_masked`

Detection-limit tests: indistinguishable commits, unrelated project, rename
threshold, moved check (not reported), fork repository never modified
(trapped hook and `core.fsmonitor`), exclusions, reverted source commit,
change origin (backport, rollback), timeline and divergence graph.
