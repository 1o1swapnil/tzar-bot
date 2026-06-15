#!/usr/bin/env bash
#
# install-hunt-tooling.sh — provision the offensive CLI tools referenced by the
# imported claude-bughunter skills (Tier 1 + Tier 2) on Kali / Debian.
#
# Idempotent: every tool is checked with `command -v` first and skipped if present.
# Grouped by installer:  apt (base)  ·  go install (PD + tomnomnom)  ·  pipx (python)  ·  git clone (rest)
#
# Usage:
#   bash tools/install-hunt-tooling.sh            # install everything missing
#   bash tools/install-hunt-tooling.sh --check    # report status only, install nothing
#   bash tools/install-hunt-tooling.sh --dry-run  # print what WOULD run
#   bash tools/install-hunt-tooling.sh --apt-only | --go-only | --pipx-only | --git-only
#
# Notes:
#   - Needs sudo for apt + system Go install. Run as your normal user (NOT root) so
#     go/pipx land in $HOME; the script calls sudo only where required.
#   - Network access required.

set -u  # deliberately NOT set -e: one failure must not abort the whole run.

# ---------------------------------------------------------------- config / args
DRY=0; CHECK=0; ONLY=""
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --check)   CHECK=1 ;;
    --apt-only)  ONLY="apt" ;;
    --go-only)   ONLY="go" ;;
    --pipx-only) ONLY="pipx" ;;
    --git-only)  ONLY="git" ;;
    -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a (try --help)"; exit 2 ;;
  esac
done

OPT_DIR="${OPT_DIR:-$HOME/opt/sec-tools}"
LOCAL_BIN="$HOME/.local/bin"
GO_BIN="$HOME/go/bin"
mkdir -p "$LOCAL_BIN"

# result accounting
declare -a R_INSTALLED R_SKIPPED R_FAILED
note() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { if [ "$DRY" = 1 ]; then echo "    DRY: $*"; return 0; fi; eval "$*"; }

want_group() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# install_tool <binary> <group> <install-command...>
install_tool() {
  local bin="$1" group="$2"; shift 2
  local cmd="$*"
  if have "$bin"; then R_SKIPPED+=("$bin"); printf '    %-20s already present (%s)\n' "$bin" "$(command -v "$bin")"; return 0; fi
  if [ "$CHECK" = 1 ]; then R_FAILED+=("$bin"); printf '    %-20s \033[1;33mMISSING\033[0m\n' "$bin"; return 0; fi
  note "installing $bin  ($group)"
  if run "$cmd" && { [ "$DRY" = 1 ] || have "$bin"; }; then
    R_INSTALLED+=("$bin"); ok "$bin installed"
  else
    R_FAILED+=("$bin"); err "$bin failed (install manually — see comment in script)"
  fi
}

# ---------------------------------------------------------------- prerequisites
ensure_prereqs() {
  [ "$CHECK" = 1 ] && return 0
  if ! have go && want_group go; then
    note "Go toolchain missing — installing golang-go via apt"
    run "sudo apt-get update -qq && sudo apt-get install -y golang-go"
  fi
  if ! have pipx && want_group pipx; then
    note "pipx missing — installing via apt"
    run "sudo apt-get install -y pipx && pipx ensurepath"
  fi
  export PATH="$GO_BIN:$LOCAL_BIN:$PATH"
}

# ============================================================ 1) APT (base)
apt_group() {
  want_group apt || return 0
  echo; echo "=== apt — base Kali tooling ==="
  # binary:package  (binary name as referenced by skills : apt package providing it)
  local pairs=(
    nmap:nmap masscan:masscan sqlmap:sqlmap ffuf:ffuf gobuster:gobuster
    nikto:nikto amass:amass wfuzz:wfuzz whatweb:whatweb wafw00f:wafw00f
    apktool:apktool jadx:jadx pandoc:pandoc nuclei:nuclei subfinder:subfinder
    naabu:naabu katana:katana dnsx:dnsx dalfox:dalfox seclists:seclists
  )
  # one upfront apt update if anything is actually missing
  if [ "$CHECK" != 1 ] && [ "$DRY" != 1 ]; then
    local need=0; for p in "${pairs[@]}"; do have "${p%%:*}" || need=1; done
    [ "$need" = 1 ] && run "sudo apt-get update -qq"
  fi
  local p bin pkg
  for p in "${pairs[@]}"; do
    bin="${p%%:*}"; pkg="${p##*:}"
    install_tool "$bin" apt "sudo apt-get install -y $pkg"
  done
}

# ============================================================ 2) GO INSTALL
go_group() {
  want_group go || return 0
  echo; echo "=== go install — ProjectDiscovery + tomnomnom suite (-> $GO_BIN) ==="
  # binary : go module path
  local pairs=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "gf:github.com/tomnomnom/gf@latest"
    "qsreplace:github.com/tomnomnom/qsreplace@latest"
    "waybackurls:github.com/tomnomnom/waybackurls@latest"
    "anew:github.com/tomnomnom/anew@latest"
    "unfurl:github.com/tomnomnom/unfurl@latest"
    "gau:github.com/lc/gau/v2/cmd/gau@latest"
    "subjack:github.com/haccer/subjack@latest"
    "subzy:github.com/PentestPad/subzy@latest"
    "puredns:github.com/d3mondev/puredns/v2@latest"
    "grpcurl:github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
    "grpcui:github.com/fullstorydev/grpcui/cmd/grpcui@latest"
    "trufflehog:github.com/trufflesecurity/trufflehog/v3@latest"
    "gitleaks:github.com/zricethezav/gitleaks/v8@latest"
  )
  local p bin mod
  for p in "${pairs[@]}"; do
    bin="${p%%:*}"; mod="${p#*:}"
    install_tool "$bin" go "GOBIN=$GO_BIN go install $mod"
  done
}

# ============================================================ 3) PIPX (python)
pipx_group() {
  want_group pipx || return 0
  echo; echo "=== pipx — python tooling (-> $LOCAL_BIN) ==="
  install_tool arjun       pipx "pipx install arjun"
  install_tool semgrep     pipx "pipx install semgrep"
  install_tool frida       pipx "pipx install frida-tools"
  install_tool paramspider pipx "pipx install git+https://github.com/devanshbatham/paramspider"
}

# ============================================================ 4) GIT CLONE (rest)
# Clones into $OPT_DIR and drops a launcher into $LOCAL_BIN so the binary name
# matches what the skills call.
git_tool() {
  local bin="$1" repo="$2" runline="$3"
  if have "$bin"; then R_SKIPPED+=("$bin"); printf '    %-20s already present\n' "$bin"; return 0; fi
  if [ "$CHECK" = 1 ]; then R_FAILED+=("$bin"); printf '    %-20s \033[1;33mMISSING\033[0m\n' "$bin"; return 0; fi
  local dir="$OPT_DIR/$(basename "$repo" .git)"
  note "cloning $bin  ($repo)"
  if [ -d "$dir/.git" ]; then run "git -C '$dir' pull --ff-only -q || true"; else run "git clone --depth 1 -q '$repo' '$dir'"; fi
  # write launcher
  if [ "$DRY" != 1 ]; then
    printf '#!/usr/bin/env bash\ncd "%s" && exec %s "$@"\n' "$dir" "$runline" > "$LOCAL_BIN/$bin"
    chmod +x "$LOCAL_BIN/$bin"
  fi
  if [ "$DRY" = 1 ] || have "$bin"; then R_INSTALLED+=("$bin"); ok "$bin installed (launcher in $LOCAL_BIN)"; else R_FAILED+=("$bin"); err "$bin failed"; fi
}

git_group() {
  want_group git || return 0
  echo; echo "=== git clone — specialist tools (-> $OPT_DIR, launchers in $LOCAL_BIN) ==="
  mkdir -p "$OPT_DIR"
  git_tool openredirex  https://github.com/devanshbatham/OpenRedireX "python3 openredirex.py"
  git_tool phpggc       https://github.com/ambionics/phpggc          "php phpggc"
  git_tool smuggler.py  https://github.com/defparam/smuggler         "python3 smuggler.py"
  git_tool h2csmuggler  https://github.com/BishopFox/h2csmuggler     "python3 h2csmuggler.py"
  git_tool jwt_tool     https://github.com/ticarpi/jwt_tool          "python3 jwt_tool.py"
  # ysoserial = prebuilt jar
  if want_group git && ! have ysoserial; then
    if [ "$CHECK" = 1 ]; then R_FAILED+=("ysoserial"); printf '    %-20s \033[1;33mMISSING\033[0m\n' ysoserial; else
      note "fetching ysoserial.jar"
      run "mkdir -p '$OPT_DIR/ysoserial' && curl -sL -o '$OPT_DIR/ysoserial/ysoserial.jar' https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar"
      if [ "$DRY" != 1 ]; then printf '#!/usr/bin/env bash\nexec java -jar "%s/ysoserial/ysoserial.jar" "$@"\n' "$OPT_DIR" > "$LOCAL_BIN/ysoserial"; chmod +x "$LOCAL_BIN/ysoserial"; fi
      have ysoserial && { R_INSTALLED+=("ysoserial"); ok "ysoserial installed"; } || { R_FAILED+=("ysoserial"); err "ysoserial failed (needs default-jre)"; }
    fi
  else have ysoserial && { R_SKIPPED+=("ysoserial"); printf '    %-20s already present\n' ysoserial; }; fi
}

# ---------------------------------------------------------------- gf patterns
gf_patterns() {
  { want_group go || want_group git; } || return 0
  [ "$CHECK" = 1 ] && return 0
  if have gf && [ ! -d "$HOME/.gf" ]; then
    note "installing gf patterns (1ndianl33t/Gf-Patterns)"
    run "git clone --depth 1 -q https://github.com/1ndianl33t/Gf-Patterns '$OPT_DIR/Gf-Patterns' && mkdir -p '$HOME/.gf' && cp '$OPT_DIR/Gf-Patterns/'*.json '$HOME/.gf/'"
  fi
}

# ---------------------------------------------------------------- PATH check
path_check() {
  echo; echo "=== PATH check ==="
  local missing=0
  for d in "$GO_BIN" "$LOCAL_BIN"; do
    case ":$PATH:" in *":$d:"*) ok "$d on PATH" ;; *) warn "$d NOT on PATH"; missing=1 ;; esac
  done
  if [ "$missing" = 1 ]; then
    warn "Add to ~/.zshrc:   export PATH=\"\$HOME/go/bin:\$HOME/.local/bin:\$PATH\""
  fi
}

# ============================================================ main
echo "tzar-bot hunt-tooling installer  (mode: $([ $CHECK = 1 ] && echo check || ([ $DRY = 1 ] && echo dry-run || echo install))${ONLY:+, group=$ONLY})"
ensure_prereqs
apt_group
go_group
pipx_group
git_group
gf_patterns
path_check

# ---------------------------------------------------------------- summary
set +u  # empty arrays expand cleanly regardless of bash version
echo; echo "================= SUMMARY ================="
printf 'installed: %d   skipped(present): %d   failed/missing: %d\n' \
  "${#R_INSTALLED[@]}" "${#R_SKIPPED[@]}" "${#R_FAILED[@]}"
[ "${#R_INSTALLED[@]}" -gt 0 ] && { echo; ok "installed:"; printf '   %s\n' "${R_INSTALLED[@]}"; }
[ "${#R_FAILED[@]}" -gt 0 ]    && { echo; err "$([ $CHECK = 1 ] && echo missing || echo failed):"; printf '   %s\n' "${R_FAILED[@]}"; }
echo
echo "Re-run with --check anytime to re-verify. Open a new shell (or source ~/.zshrc) after first install so PATH picks up new bins."
[ "${#R_FAILED[@]}" -gt 0 ] && [ "$CHECK" != 1 ] && exit 1 || exit 0
