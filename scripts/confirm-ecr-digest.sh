#!/usr/bin/env bash
# Confirm the immutable ECR digest for a freshly pushed image tag and pin a
# compose env-override to it.
#
# A pushed `:latest` (and even `:<sha>`) tag is mutable and may not yet be
# readable right after `docker push` due to ECR eventual consistency. Before
# we trigger a redeploy we resolve the immutable content digest for the SHA
# tag and gate on it: no confirmed digest -> non-zero exit, no env file
# written, so the caller aborts BEFORE `docker compose pull`.
#
# Usage:
#   confirm-ecr-digest.sh <repo_uri> <tag> <out_env_file> <image_var_name>
#
# On success appends `<image_var_name>=<repo_uri>@<digest>` to <out_env_file>,
# so a compose file referencing ${<image_var_name>:-<default>} pulls the exact
# confirmed digest rather than a mutable tag.
#
# Tunables (env):
#   CONFIRM_DIGEST_RETRIES      retry attempts for describe-images (default 12)
#   CONFIRM_DIGEST_RETRY_SLEEP  seconds between attempts (default 5)
#   AWS_REGION                  passed through to `aws` if set
set -eu

REPO_URI="${1:?repo_uri required}"
TAG="${2:?image tag required}"
OUT_ENV="${3:?out env file required}"
VAR_NAME="${4:?image var name required}"

RETRIES="${CONFIRM_DIGEST_RETRIES:-12}"
SLEEP_S="${CONFIRM_DIGEST_RETRY_SLEEP:-5}"

# Repository name is the path component after the registry host.
REPO_NAME="${REPO_URI##*/}"

region_args=""
if [ -n "${AWS_REGION:-}" ]; then
  region_args="--region ${AWS_REGION}"
fi

DIGEST=""
attempt=1
while [ "${attempt}" -le "${RETRIES}" ]; do
  # shellcheck disable=SC2086
  DIGEST="$(aws ecr describe-images ${region_args} \
    --repository-name "${REPO_NAME}" \
    --image-ids "imageTag=${TAG}" \
    --query 'imageDetails[0].imageDigest' \
    --output text 2>/dev/null || true)"
  case "${DIGEST}" in
    sha256:*)
      break
      ;;
    *)
      DIGEST=""
      echo "digest not yet visible for ${REPO_NAME}:${TAG} (attempt ${attempt}/${RETRIES})"
      ;;
  esac
  attempt=$((attempt + 1))
  [ "${attempt}" -le "${RETRIES}" ] && sleep "${SLEEP_S}"
done

if [ -z "${DIGEST}" ]; then
  echo "ERROR: could not confirm an immutable ECR digest for ${REPO_NAME}:${TAG}; refusing to redeploy" >&2
  exit 1
fi

echo "${VAR_NAME}=${REPO_URI}@${DIGEST}" >> "${OUT_ENV}"
echo "confirmed digest: ${REPO_URI}@${DIGEST}"
