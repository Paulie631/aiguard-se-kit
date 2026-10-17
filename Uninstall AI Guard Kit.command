#!/bin/bash
# AI Guard SE Demo Kit - uninstall (macOS).
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/aiguard-kit" uninstall
read -r -p "  Press Return to close. "
