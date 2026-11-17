#!/usr/bin/env bash
# Fails when agent material is tracked, or when finding, wave or work-package IDs or planning-doc
# references sit in code or strings.
# Needs a git checkout (git ls-files, git grep).
set -euo pipefail
cd "$(dirname "$0")/.."
# Outside a checkout git grep fails and every check below would pass without looking.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo 'ai check: needs a git checkout' >&2; exit 1; }

# The doc names are written with a bracket (PORTIN[G]) so that this file does not match its own patterns.
ai_files='(^|/)(AGENTS|CLAUDE|GEMINI)\.md$|(^|/)\.claude/|copilot-instructions|port-statu[s]|PORTIN[G]\.md'
ai_ids='(^|[^A-Za-z0-9_])(K-[0-9]{2,3}|[Ww]ave[- ]?[0-9]+|WP-[0-9]+|DEC-[0-9]+|FSD-[0-9]+|BR-[0-9]+|ADR-[0-9]+|CF-[0-9]+|SP-[0-9]+|TG-[0-9]+|OD-[0-9]+|CU-[0-9]+|RK-[0-9]+|POC-[A-Z]+)([^0-9]|$)'
ai_docs='(^|[^A-Za-z0-9_])(PORTIN[G]|port-statu[s]|docs/plan[s]/|[Pp]lan §[0-9]|[Ss]pec §[0-9])'

# No \b (macOS git grep -E matches nothing with it) and no grep -q after a pipe (SIGPIPE under pipefail).
# The samples are built with printf so this file does not match its own patterns.
[ "$(printf 'x K-%s y\n' 12 | grep -cE "$ai_ids")" = 1 ] || { echo 'ai check: pattern self-test failed' >&2; exit 1; }
[ "$(printf 'x POC-%s y\n' FCGI | grep -cE "$ai_ids")" = 1 ] || { echo 'ai check: pattern self-test failed' >&2; exit 1; }
[ "$(printf 'see %s/plans/x\n' docs | grep -cE "$ai_docs")" = 1 ] || { echo 'ai check: pattern self-test failed' >&2; exit 1; }
if git ls-files | grep -E "$ai_files"; then echo 'ai check: agent files tracked' >&2; exit 1; fi
# proto/ is vendored from wafio-cp-backend and checked there (scripts/sync-proto.sh), so it is skipped here.
if git grep -nIE "$ai_ids" -- ':!*.md' ':!proto/'; then echo 'ai check: IDs in code or strings' >&2; exit 1; fi
if git grep -nIE "$ai_docs" -- ':!*.md' ':!proto/'; then echo 'ai check: planning docs referenced in code or strings' >&2; exit 1; fi
echo 'ai check: clean'
