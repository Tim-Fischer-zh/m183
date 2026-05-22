#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#  demo.sh — orchestriert die Aufnahme des A07-Screencasts.
#  Startet Server und Exploit in der richtigen Reihenfolge.
#
#  Verwendung:
#    ./demo.sh         beide Phasen (verwundbar, dann gepinnt)
#    ./demo.sh vuln    nur Phase 1 (verwundbar)
#    ./demo.sh fixed   nur Phase 2 (Fix)
# ════════════════════════════════════════════════════════════════════
set -euo pipefail

# Immer aus dem Projektverzeichnis arbeiten.
cd "$(dirname "$0")"

PORT="${PORT:-3000}"
export NODE_NO_WARNINGS=1

if [ ! -d node_modules ]; then
  echo "node_modules fehlt. Bitte zuerst ausführen:  npm install" >&2
  exit 1
fi

SERVER_PID=""
LAST_CHECK=""

cleanup() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
}
trap cleanup EXIT

# Wartet, bis der Server Anfragen beantwortet. curl wiederholt bei
# "connection refused", bis /public-key erreichbar ist.
wait_ready() {
  if curl -s -o /dev/null --retry 40 --retry-connrefused --retry-delay 1 \
       --max-time 30 "http://localhost:${PORT}/public-key"; then
    return 0
  fi
  echo "FEHLER: Server wurde nicht rechtzeitig bereit." >&2
  exit 1
}

# run_phase <VULNERABLE-Wert> <Banner> <erwartet: ERFOLGREICH|ABGEWEHRT>
run_phase() {
  local mode="$1" label="$2" expect="$3"
  local logfile="/tmp/a07-demo-server-${mode}.log"
  local outfile="/tmp/a07-demo-exploit-${mode}.out"

  printf '\n================================================================\n'
  printf '  %s\n' "$label"
  printf '================================================================\n'

  VULNERABLE="$mode" node src/server.js >"$logfile" 2>&1 &
  SERVER_PID=$!
  wait_ready

  node exploit/exploit.js | tee "$outfile" || true
  cleanup

  printf '\n  (Server-Log: %s)\n' "$logfile"

  if grep -q "ERGEBNIS: ANGRIFF ${expect}" "$outfile"; then
    LAST_CHECK="PASS"
  else
    LAST_CHECK="FAIL"
  fi
}

PHASE="${1:-both}"
case "$PHASE" in
  both|vuln|fixed) ;;
  *) echo "Unbekanntes Argument: $PHASE  (erlaubt: vuln | fixed | <leer>)" >&2; exit 1 ;;
esac

SUMMARY=""

if [ "$PHASE" = both ] || [ "$PHASE" = vuln ]; then
  run_phase true 'PHASE 1 — Server VERWUNDBAR (der Angriff muss gelingen)' ERFOLGREICH
  SUMMARY="${SUMMARY}  Phase 1 (verwundbar):  ${LAST_CHECK}  — erwartet: Angriff erfolgreich\n"
fi

if [ "$PHASE" = both ] || [ "$PHASE" = fixed ]; then
  run_phase false 'PHASE 2 — Server GEPINNT / FIX (der Angriff muss scheitern)' ABGEWEHRT
  SUMMARY="${SUMMARY}  Phase 2 (gepinnt):     ${LAST_CHECK}  — erwartet: Angriff abgewehrt\n"
fi

printf '\n================================================================\n'
printf '  SELBSTCHECK\n'
printf '================================================================\n'
printf '%b' "$SUMMARY"
printf '\n'
