#!/bin/sh
BRANCH=$(git branch | awk '/\*/ { print $2; }')
VERSION_START="$(git log -n 1 --date=short --format=format:"%ad." HEAD)"
VERSION_END="$(git log -n 1 --date=short --format=format:".%H" HEAD)"
echo "{\"version\": \"$VERSION_START$BRANCH$VERSION_END\"}" > public/cli/build.json
echo "BUILD VERSION: $VERSION_START$BRANCH$VERSION_END"
