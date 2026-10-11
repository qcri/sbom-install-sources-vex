#!/bin/sh
# Run inside a variant container: OS, package manager records, Python metadata, checksums, ground truth.
PY=${PY:-python3}
echo "### os";               grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
echo "### dpkg python3-yaml"
if dpkg-query -W python3-yaml >/dev/null 2>&1; then
  dpkg-query -W -f='${Package} ${Version} ${Status}\n' python3-yaml
  echo "-- md5sums recorded by dpkg (constructor.py):"; grep 'yaml/constructor.py' /var/lib/dpkg/info/python3-yaml.md5sums
  echo "-- dpkg --verify (no output = files match dpkg's md5sums):"; dpkg --verify python3-yaml
else
  echo "not installed"
fi
echo "### python metadata (importlib.metadata)"; $PY /app/evidence.py
echo "### ground truth (oracle)";                 $PY /app/oracle.py
