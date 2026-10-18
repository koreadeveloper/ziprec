#!/bin/sh
# build_app.sh — ZipRec.app 조립 (Xcode 프로젝트 없이 swiftc 직접 사용)
# 실행: sh gui/build_app.sh   →   gui/ZipRec.app 생성
set -e
cd "$(dirname "$0")/.."

echo "[1/3] ziprec CLI 빌드"
make >/dev/null

echo "[2/3] 앱 번들 조립"
APP=gui/ZipRec.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp gui/Info.plist "$APP/Contents/Info.plist"
cp ziprec "$APP/Contents/Resources/ziprec"          # GUI가 번들 내부 바이너리 사용
cp tests/fixtures/mini.dict "$APP/Contents/Resources/" 2>/dev/null || true
cp -R gui/*.lproj "$APP/Contents/Resources/" 2>/dev/null || true   # localizations
# vendored perl module for 7z2john.pl (Compress::Raw::Lzma)
[ -d tools/perl5 ] && cp -R tools/perl5 "$APP/Contents/Resources/perl5"

echo "[3/3] SwiftUI 프론트엔드 컴파일"
swiftc -O -parse-as-library \
       -target arm64-apple-macosx13.0 \
       -o "$APP/Contents/MacOS/ZipRec" \
       gui/ZipRecApp.swift

# ad-hoc 서명 (로컬 실행용; Gatekeeper 경고 완화)
codesign --force --deep --sign - "$APP" 2>/dev/null || true

echo
echo "완료: $APP"
echo "실행: open $APP   (또는 Finder에서 더블클릭)"
