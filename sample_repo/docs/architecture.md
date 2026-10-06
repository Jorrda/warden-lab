# Architecture

The portal is a Flask application behind gunicorn. Documents live in S3, reports come from a MySQL replica, alerts go to Slack, and payments run through Stripe. Infrastructure is described in `infra/`.
