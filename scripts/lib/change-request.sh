# Maker-checker helpers for the pilot scripts (ADR-009). Source after setting
# API, ACTOR and APPROVER.
#
# Credentials: OIDC access tokens (PILOT_ACTOR_TOKEN proposes,
# PILOT_APPROVER_TOKEN approves), or — only when the API runs with
# --insecure-dev — the self-asserted X-Kavach-Principal header.

if [[ -n "${PILOT_ACTOR_TOKEN:-}" ]]; then
  actor_auth=(-H "Authorization: Bearer ${PILOT_ACTOR_TOKEN}")
else
  actor_auth=(-H "X-Kavach-Principal: ${ACTOR}")
fi
if [[ -n "${PILOT_APPROVER_TOKEN:-}" ]]; then
  approver_auth=(-H "Authorization: Bearer ${PILOT_APPROVER_TOKEN}")
else
  approver_auth=(-H "X-Kavach-Principal: ${APPROVER}")
fi

json_field() {
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

# propose_change <kind> <params-json> — prints the pending request JSON.
propose_change() {
  curl -fsS -X POST "${API}/v1/change-requests" \
    -H "Content-Type: application/json" \
    "${actor_auth[@]}" \
    -d "{\"kind\":\"$1\",\"params\":$2}"
}

# approve_change <request-json> [curl credential args...] — approves with the
# digest from the proposal; prints the applied request JSON.
approve_change() {
  local request="$1"
  shift
  local creds=("${approver_auth[@]}")
  if [[ $# -gt 0 ]]; then
    creds=("$@")
  fi
  curl -fsS -X POST "${API}/v1/change-requests/$(json_field "$request" id)/approve" \
    -H "Content-Type: application/json" \
    "${creds[@]}" \
    -d "{\"change_digest\":\"$(json_field "$request" change_digest)\"}"
}

# cancel_change <request-json> — the proposer withdraws a pending request.
cancel_change() {
  curl -fsS -X POST "${API}/v1/change-requests/$(json_field "$1" id)/cancel" \
    "${actor_auth[@]}" >/dev/null
}

# apply_change <kind> <params-json> — propose as ACTOR, approve as APPROVER.
apply_change() {
  local request
  request="$(propose_change "$1" "$2")"
  approve_change "$request"
}
