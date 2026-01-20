import os
import json
from prance import ResolvingParser
from pathlib import Path

dir_path = Path(os.path.abspath(__file__)).parent
print(dir_path)
spec_path = os.path.join(dir_path.parent, "openapi", "openapi.yaml")
print(spec_path)

parser = ResolvingParser(spec_path)

UserSchema = parser.specification['components']['schemas']['User']
