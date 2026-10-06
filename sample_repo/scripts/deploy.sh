#!/usr/bin/env bash
set -euo pipefail
# Deploys the current build; the token below was pasted in for a hotfix and never removed.
GITHUB_TOKEN="ghp_EVGM6eUtBE4aZZsqezFALbfaCLUrv9MdEPXB"
curl -sf -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/fleetline/portal/deployments
scp -r web/static/dist portal@portal.fleetline.internal:/srv/portal/web/static/
