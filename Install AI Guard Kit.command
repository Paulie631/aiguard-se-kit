#!/bin/bash
# AI Guard SE Demo Kit - double-click installer for macOS.
cd "$(dirname "$0")" || exit 1
clear
cat <<'EOF'

  AI Guard SE Demo Kit - installer
  ================================
  This will:
    - install uv (the free tool the kit runs on) if it isn't installed yet
    - copy the kit to ~/.aiguard-se-kit/app
    - add an "AI Guard Demo Console" shortcut to your Desktop
    - let you run "aiguard-kit" from any terminal
  Nothing changes in your Zscaler tenant until you finish Setup in the console.

EOF
read -r -p "  Press Return to install, or close this window to cancel. "

find_uv() {
  UV="$(command -v uv || true)"
  for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -z "$UV" ] && [ -x "$c" ] && UV="$c"
  done
}
fail() { echo; echo "  $1"; echo; read -r -p "  Press Return to close. "; exit 1; }

find_uv
if [ -z "$UV" ]; then
  echo; echo "  Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  find_uv
fi
if [ -z "$UV" ] && command -v brew >/dev/null; then
  echo "  The uv installer didn't work here. Trying Homebrew..."
  brew install uv
  find_uv
fi
[ -z "$UV" ] && fail "Couldn't install uv. Your laptop's security policy may be blocking the download. Ask IT to allow astral.sh and github.com, or see https://docs.astral.sh/uv/getting-started/installation/ - then double-click this installer again."

export UV_SYSTEM_CERTS=1 UV_NATIVE_TLS=1
echo; echo "  Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)..."
"$UV" run --quiet --python 3.12 --script ./aiguard_kit.py install || fail "Install failed. The message above says why."
echo; echo "  Opening the console. Keep this window open while you use it; close it to stop the console."
exec "$HOME/.aiguard-se-kit/app/aiguard-kit" gui
