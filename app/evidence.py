"""Package metadata and checksums for every installed PyYAML distribution."""
import base64, hashlib, json
from importlib import metadata
from pathlib import Path

out = []
for dist in metadata.distributions():
    if (dist.metadata["Name"] or "").lower() != "pyyaml":
        continue
    info = Path(str(dist._path))
    d = {"metadata dir": str(info), "Name": dist.metadata["Name"], "Version": dist.version}
    for f in ("INSTALLER", "REQUESTED", "direct_url.json"):
        if (info / f).exists():
            d[f] = (info / f).read_text().strip()
    if (info / "RECORD").exists():     # pip: verify every recorded sha256 against the file on disk
        ok, bad, ctor = 0, [], None
        for line in (info / "RECORD").read_text().splitlines():
            path, h, _ = line.rsplit(",", 2)
            if not h:
                continue
            algo, want = h.split("=", 1)
            p = (info.parent / path).resolve()
            got = base64.urlsafe_b64encode(hashlib.new(algo, p.read_bytes()).digest()).rstrip(b"=").decode()
            ok, bad = (ok + 1, bad) if got == want else (ok, bad + [path])
            if path.endswith("yaml/constructor.py"):
                ctor = {"RECORD entry": h, "sha256 hex": base64.urlsafe_b64decode(want + "==").hex()}
        d["RECORD check"] = {"files ok": ok, "mismatches": bad}
        d["RECORD constructor.py"] = ctor
    else:
        d["RECORD"] = "none (not installed by pip)"
    out.append(d)
print(json.dumps(out, indent=2))
