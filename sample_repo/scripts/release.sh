#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:?version}"
curl -sf -X POST -H "Authorization: token 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" \
  https://api.github.com/repos/fleetline/portal/releases -d "{\"tag_name\": \"$VERSION\"}"
