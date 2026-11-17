"""Validate a CycloneDX 1.6 JSON file against the official schema (and its $refs)."""
import json
import pathlib
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

schema_dir = pathlib.Path(sys.argv[1])
resources = []
for p in schema_dir.glob("*.json"):
    doc = json.loads(p.read_text(encoding="utf-8"))
    res = Resource.from_contents(doc, default_specification=DRAFT7)
    resources.append((p.name, res))
    if "$id" in doc:
        resources.append((doc["$id"], res))
registry = Registry().with_resources(resources)
schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text(encoding="utf-8"))
validator = Draft7Validator(schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)
bad = 0
for f in sys.argv[2:]:
    doc = json.loads(pathlib.Path(f).read_text(encoding="utf-8"))
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    for e in errors[:20]:
        print(f"{f}: {'/'.join(map(str, e.path))}: {e.message[:300]}")
    print(f"{f}: {'valid' if not errors else str(len(errors)) + ' errors'} (CycloneDX 1.6 JSON schema)")
    bad += bool(errors)
sys.exit(1 if bad else 0)
