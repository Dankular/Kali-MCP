#!/bin/sh
set -eu
cd /opt/kali-mcp
available=$(df -Pk . | awk 'NR==2 {print $4}')
if [ "$available" -lt 89128960 ]; then
    echo 'Full-image build requires at least 85 GiB free for installation and export.' >&2
    exit 1
fi
docker buildx build -f docker/Dockerfile.everything \
    --output type=image,name=kali-mcp:everything,unpack=false,compression=zstd,compression-level=1,oci-mediatypes=true docker
echo 'Full image built. Run sh activate-everything.sh to prepare the catalog and activate it.'
