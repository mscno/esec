#!/bin/sh
# Build the local Esec browser and its matching CLI. No helper or daemon.
set -eu
cd "$(dirname "$0")"
version=${ESEC_VERSION:-dev}
swift build -c release
swiftbin=$(swift build -c release --show-bin-path)
app="$PWD/build/Esec.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$swiftbin/Esec" "$app/Contents/MacOS/EsecApp"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
(cd ../.. && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$version -X main.commit=$(git rev-parse --short HEAD)" -o "$app/Contents/MacOS/esec" ./cmd/esec)
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.mscno.esec</string>
<key>CFBundleName</key><string>Esec</string>
<key>CFBundleDisplayName</key><string>Esec</string>
<key>CFBundleExecutable</key><string>EsecApp</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>NSHumanReadableCopyright</key><string>Copyright © Mads Schou</string>
</dict></plist>
PLIST
codesign --force --sign - "$app/Contents/MacOS/esec"
codesign --force --sign - --options runtime "$app"
codesign --verify --deep --strict "$app"
echo "Built $app"
