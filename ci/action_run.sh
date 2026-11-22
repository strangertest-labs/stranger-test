#!/usr/bin/env bash
# Runs `stranger-test scan` or `stranger-test confirm` for the GitHub Action
# (action.yml). Every input arrives as an environment variable, never spliced
# into the command line by the workflow, so a token or URL cannot inject shell.
#
#   ST_MODE               scan | confirm                      (default: scan)
#   ST_URL                endpoint to test (agent-memory, semantic-cache: the base URL) (required)
#   ST_TEST               confirm only: which deep test       (e.g. state-handle)
#   ST_TOKEN_A/ST_TOKEN_B confirm only: the two identities' bearer tokens
#   ST_NAMESPACE_A/_B     agent-memory only: Store namespaces, dotted (alice.notes)
#   ST_ASSISTANT          agent-memory only: assistant (graph) id to run
#   ST_SAVE_INPUT         agent-memory only: JSON run input that saves; {marker} is replaced
#   ST_RECALL_INPUT       agent-memory only: JSON run input that recalls
#   ST_WHOAMI_FIELD       agent-memory only: run-output field carrying the caller's identity
#   semantic-cache only (each maps to the --flag of the same name; see docs/CACHE.md):
#   ST_CACHE_MODE         store | chat
#   ST_IDENTITY_AS        header | bearer: how ST_TOKEN_A/_B are sent
#   ST_IDENTITY_HEADER    header that carries each identity's id (default x-identity)
#   ST_TOKEN_HEADER       header that carries a token or API key (default Authorization)
#   ST_TOKEN_SIBLING      a third, prefix-sibling identity
#   ST_API_KEY            one credential shared by every request
#   ST_USER_A/_B/_SIBLING chat mode: values for the OpenAI "user" body field
#   ST_STORE_PATH/ST_QUERY_PATH/ST_CHAT_PATH   request paths
#   ST_MODEL              chat mode: model name to request
#   ST_CACHE_HIT_HEADER   chat mode: response header that tells a cache hit
#   ST_BASE_QUERY/ST_REWORDED_QUERY/ST_THRESHOLD   the question pair and threshold
#   ST_BEARER             scan only: optional bearer token
#   ST_SARIF_FILE         scan only: also write a SARIF 2.1.0 log to this path
#   ST_ALLOW_NONLOOPBACK  "true" to permit a non-loopback target you may test
#   ST_FAIL_ON            leak | inconclusive | never         (default: leak)
#                         An unreachable scan target fails under leak and
#                         inconclusive alike: nothing was tested.
#   ST_CMD                command to invoke                   (default: stranger-test)
#
# Exit: 0 pass, 1 failed the gate, 3 bad input.
set -u

mode="${ST_MODE:-scan}"
url="${ST_URL:-}"
fail_on="${ST_FAIL_ON:-leak}"
# ST_CMD may be several words (tests use "python3 -m strangertest").
read -r -a cmd <<< "${ST_CMD:-stranger-test}"

if [ -z "$url" ]; then
  echo "stranger-test action: 'url' is required" >&2
  exit 3
fi
case "$fail_on" in
  leak|inconclusive|never) ;;
  *) echo "stranger-test action: fail-on must be leak, inconclusive or never" >&2; exit 3 ;;
esac

extra=()
if [ "${ST_ALLOW_NONLOOPBACK:-false}" = "true" ]; then
  extra+=(--allow-nonloopback)
fi

code=0
case "$mode" in
  scan)
    args=(scan "$url")
    if [ -n "${ST_BEARER:-}" ]; then args+=(--bearer "$ST_BEARER"); fi
    if [ -n "${ST_SARIF_FILE:-}" ]; then
      # SARIF to the file; the gate decision comes from this run's exit code.
      "${cmd[@]}" "${args[@]}" ${extra[@]+"${extra[@]}"} --sarif > "$ST_SARIF_FILE" || code=$?
      echo "SARIF written to $ST_SARIF_FILE"
    else
      "${cmd[@]}" "${args[@]}" ${extra[@]+"${extra[@]}"} || code=$?
    fi
    # scan: 0 no signal, 1 at least one signal, 2 unreachable.
    ;;
  confirm)
    if [ -z "${ST_TEST:-}" ]; then
      echo "stranger-test action: mode 'confirm' needs 'test' (see: stranger-test confirm --list)" >&2
      exit 3
    fi
    args=(confirm "$ST_TEST" "$url")
    if [ -n "${ST_TOKEN_A:-}" ]; then args+=(--token-a "$ST_TOKEN_A"); fi
    if [ -n "${ST_TOKEN_B:-}" ]; then args+=(--token-b "$ST_TOKEN_B"); fi
    # Options only the agent-memory test uses; other tests ignore them.
    if [ -n "${ST_NAMESPACE_A:-}" ]; then args+=(--namespace-a "$ST_NAMESPACE_A"); fi
    if [ -n "${ST_NAMESPACE_B:-}" ]; then args+=(--namespace-b "$ST_NAMESPACE_B"); fi
    if [ -n "${ST_ASSISTANT:-}" ]; then args+=(--assistant "$ST_ASSISTANT"); fi
    if [ -n "${ST_SAVE_INPUT:-}" ]; then args+=(--save-input "$ST_SAVE_INPUT"); fi
    if [ -n "${ST_RECALL_INPUT:-}" ]; then args+=(--recall-input "$ST_RECALL_INPUT"); fi
    if [ -n "${ST_WHOAMI_FIELD:-}" ]; then args+=(--whoami-field "$ST_WHOAMI_FIELD"); fi
    # Options only the semantic-cache test uses; other tests ignore them.
    if [ -n "${ST_CACHE_MODE:-}" ]; then args+=(--cache-mode "$ST_CACHE_MODE"); fi
    if [ -n "${ST_IDENTITY_AS:-}" ]; then args+=(--identity-as "$ST_IDENTITY_AS"); fi
    if [ -n "${ST_IDENTITY_HEADER:-}" ]; then args+=(--identity-header "$ST_IDENTITY_HEADER"); fi
    if [ -n "${ST_TOKEN_HEADER:-}" ]; then args+=(--token-header "$ST_TOKEN_HEADER"); fi
    if [ -n "${ST_TOKEN_SIBLING:-}" ]; then args+=(--token-sibling "$ST_TOKEN_SIBLING"); fi
    if [ -n "${ST_API_KEY:-}" ]; then args+=(--api-key "$ST_API_KEY"); fi
    if [ -n "${ST_USER_A:-}" ]; then args+=(--user-a "$ST_USER_A"); fi
    if [ -n "${ST_USER_B:-}" ]; then args+=(--user-b "$ST_USER_B"); fi
    if [ -n "${ST_USER_SIBLING:-}" ]; then args+=(--user-sibling "$ST_USER_SIBLING"); fi
    if [ -n "${ST_STORE_PATH:-}" ]; then args+=(--store-path "$ST_STORE_PATH"); fi
    if [ -n "${ST_QUERY_PATH:-}" ]; then args+=(--query-path "$ST_QUERY_PATH"); fi
    if [ -n "${ST_CHAT_PATH:-}" ]; then args+=(--chat-path "$ST_CHAT_PATH"); fi
    if [ -n "${ST_MODEL:-}" ]; then args+=(--model "$ST_MODEL"); fi
    if [ -n "${ST_CACHE_HIT_HEADER:-}" ]; then args+=(--cache-hit-header "$ST_CACHE_HIT_HEADER"); fi
    if [ -n "${ST_BASE_QUERY:-}" ]; then args+=(--base-query "$ST_BASE_QUERY"); fi
    if [ -n "${ST_REWORDED_QUERY:-}" ]; then args+=(--reworded-query "$ST_REWORDED_QUERY"); fi
    if [ -n "${ST_THRESHOLD:-}" ]; then args+=(--threshold "$ST_THRESHOLD"); fi
    "${cmd[@]}" "${args[@]}" ${extra[@]+"${extra[@]}"} || code=$?
    # confirm: 0 OK, 1 LEAK/FAIL, 2 INCONCLUSIVE or OBSERVATION, 3 usage/refusal.
    ;;
  *)
    echo "stranger-test action: mode must be scan or confirm" >&2
    exit 3
    ;;
esac

echo "stranger-test exit code: $code (fail-on: $fail_on)"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "exit-code=$code" >> "$GITHUB_OUTPUT"
fi

if [ "$code" -eq 3 ]; then exit 3; fi          # usage error / refused target
if [ "$fail_on" = "never" ]; then exit 0; fi
if [ "$code" -eq 1 ]; then exit 1; fi
if [ "$code" -eq 2 ]; then
  if [ "$mode" = "scan" ]; then
    # Nothing was tested. Passing here would be a false "clean".
    echo "::error::stranger-test could not reach the target; nothing was scanned."
    exit 1
  fi
  if [ "$fail_on" = "inconclusive" ]; then exit 1; fi
  echo "::warning::stranger-test confirm could not decide (INCONCLUSIVE or OBSERVATION). This is not a pass; read the output."
fi
exit 0
