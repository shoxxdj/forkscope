#!/usr/bin/env bash
# Builds a demo source project and a fork of it, then runs ForkScope on them.
# The example reports in examples/ were produced with this script.
#
#   ./examples/demo.sh [path/to/forkscope]
set -euo pipefail

BIN="$(realpath "${1:-$(dirname "$0")/../target/release/forkscope}")"
DEMO="${DEMO_DIR:-/tmp/forkscope-demo}"
rm -rf "$DEMO" && mkdir -p "$DEMO"
export GIT_CONFIG_NOSYSTEM=1 HOME="$DEMO"
git config --global init.defaultBranch main
git config --global commit.gpgsign false

ts=$(( $(date +%s) - 40*86400 ))
as() { # as <name> <git command...>
  local who="$1"; shift
  ts=$((ts + 86400*3))
  GIT_AUTHOR_NAME="$who" GIT_AUTHOR_EMAIL="$who@example.org" \
  GIT_COMMITTER_NAME="$who" GIT_COMMITTER_EMAIL="$who@example.org" \
  GIT_AUTHOR_DATE="@$ts +0000" GIT_COMMITTER_DATE="@$ts +0000" git "$@"
}

# ---------------------------------------------------------------- source
UP="$DEMO/acme-api"
mkdir -p "$UP/app" && cd "$UP" && git init -q
cat > app/auth.py <<'EOF'
import jwt


def login(user, password):
    if not check_password(user, password):
        raise PermissionDenied()
    return create_session(user)


def decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
EOF
cat > app/admin.py <<'EOF'
def delete_user(request, user_id):
    if not request.user.is_admin:
        return forbidden()
    User.objects.get(id=user_id).delete()
    return ok()
EOF
cat > app/client.py <<'EOF'
import requests


def call(url):
    return requests.get(url, timeout=5).json()
EOF
printf 'requests==2.31.0\nPyJWT==2.8.0\n' > requirements.txt
printf '# ACME API\n' > README.md
printf '## 1.0.0\n- first release\n' > CHANGELOG.md
as Maintainer add -A && as Maintainer commit -qm "initial release" && as Maintainer tag v1.0.0
printf 'def health():\n    return "ok"\n' > app/health.py
printf '## 1.1.0\n- health\n\n## 1.0.0\n- first release\n' > CHANGELOG.md
as Maintainer add -A && as Maintainer commit -qm "endpoint health" && as Maintainer tag v1.1.0
sed -i 's/timeout=5/timeout=5, allow_redirects=False/' app/client.py
printf 'LIMIT = 100\n\n\ndef allow(ip):\n    return hits(ip) < LIMIT\n' > app/ratelimit.py
as Maintainer add -A && as Maintainer commit -qm "security: disable redirects (CVE-2099-0001), rate limiting"

# ---------------------------------------------------------------- fork
CL="$DEMO/acme-api-fork"
git clone -q "$UP" "$CL" && cd "$CL" && git checkout -q -B main v1.1.0
python3 - <<'EOF'
import re
p = "app/admin.py"
s = open(p).read().replace("    if not request.user.is_admin:\n        return forbidden()\n", "")
open(p, "w").write(s)
EOF
as Contractor commit -qam "cleanup"
sed -i 's/timeout=5)/timeout=5, verify=False)/' app/client.py
printf 'requests==2.31.0\nPyJWT==2.8.0\nacme-internal-utils==0.1.0\n--extra-index-url https://pypi.acme-mirror.example/simple\n' > requirements.txt
as Contractor commit -qam "corporate proxy"
# fake key assembled at runtime so that it never appears verbatim in the repository
FAKE_KEY="AKIA""Q4EXAMPLE7DEMO42"
cat > app/settings.py <<EOF
DEBUG = True
AWS_ACCESS_KEY_ID = "$FAKE_KEY"
DATABASE_URL = "postgres://admin:Sup3rS3cret@db.internal:5432/acme"
EOF
as Contractor add -A && as Contractor commit -qm "configuration"
# backport of a newer source file (expected origin: source)
git checkout -q origin/main -- app/ratelimit.py
as Contractor commit -qm "add rate limiting"
# uncommitted change + untracked file
sed -i 's/algorithms=\["HS256"\]/algorithms=["HS256", "none"]/' app/auth.py
echo "deployment notes" > NOTES.txt

# ---------------------------------------------------------------- analysis
cd "$DEMO"
"$BIN" --client "$CL" --upstream "$UP" --output "$DEMO/report" --no-color
echo
echo "Reports: $DEMO/report"
