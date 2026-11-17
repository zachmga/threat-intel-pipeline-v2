#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
  echo "This scheduler is for macOS only." >&2
  exit 1
fi

label=dev.threatintel.pipeline.v2.hourly
agent_dir="$HOME/Library/LaunchAgents"
agent_file="$agent_dir/$label.plist"
user_domain="gui/$(id -u)"

case "${1:-}" in
  install)
    repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
    if [ ! -x "$repo_dir/bin/intel" ] || [ ! -f "$repo_dir/config.json" ]; then
      echo "Build bin/intel and copy config.example.json to config.json first." >&2
      exit 1
    fi
    mkdir -p "$agent_dir" "$repo_dir/output"
    xml_escape() {
      printf '%s' "$1" | sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"
    }
    repo_xml=$(xml_escape "$repo_dir")
    binary_xml=$(xml_escape "$repo_dir/bin/intel")
    out_xml=$(xml_escape "$repo_dir/output/launchd.stdout.log")
    err_xml=$(xml_escape "$repo_dir/output/launchd.stderr.log")
    cat > "$agent_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array><string>$binary_xml</string><string>run</string></array>
  <key>WorkingDirectory</key><string>$repo_xml</string>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$out_xml</string>
  <key>StandardErrorPath</key><string>$err_xml</string>
</dict>
</plist>
EOF
    plutil -lint "$agent_file"
    launchctl bootout "$user_domain" "$agent_file" 2>/dev/null || true
    launchctl bootstrap "$user_domain" "$agent_file"
    echo "Installed $agent_file"
    ;;
  uninstall)
    if [ -f "$agent_file" ]; then
      launchctl bootout "$user_domain" "$agent_file" 2>/dev/null || true
      rm "$agent_file"
    fi
    echo "Removed $label"
    ;;
  *)
    echo "Usage: sh scripts/macos-hourly.sh install|uninstall" >&2
    exit 2
    ;;
esac
