#!/bin/bash

# Read version from __init__.py using Python and store it in a shell variable
VERSION=$(python -c "exec(open('src/kessr/__init__.py').read()); print(__version__)")

echo "Version: ${VERSION}"

rm build/*
rm dist/*

# Now you can use the VERSION variable in your script
python -m build --sdist
python -m build --wheel
python scripts/upload.py --access-key "${SPACES_ACCESS_KEY}" --secret-key "${SPACES_SECRET_KEY}" --region "${SPACES_REGION}" --bucket "healthkeri-deployment" --object-key "kessr/kessr-${VERSION}.tar.gz" --file "dist/kessr-${VERSION}.tar.gz"
python scripts/upload.py --access-key "${SPACES_ACCESS_KEY}" --secret-key "${SPACES_SECRET_KEY}" --region "${SPACES_REGION}" --bucket "healthkeri-deployment" --object-key "kessr/kessr-${VERSION}-py3-none-any.whl" --file "dist/kessr-${VERSION}-py3-none-any.whl"
