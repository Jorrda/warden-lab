#!/usr/bin/env bash
set -euo pipefail
export PGPASSWORD="hSqbq38rqN8mYQdMDdNHwLBB"
pg_dump -h db-prod.fleetline.internal -U portal_app fleetline | gzip > /backups/fleetline-$(date +%F).sql.gz
