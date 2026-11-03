import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "examples" / "fixtures"


@pytest.fixture
def github_snap():
    return copy.deepcopy(json.loads((FIXTURES / "github-acme.json").read_text()))


@pytest.fixture
def aws_snap():
    return copy.deepcopy(json.loads((FIXTURES / "aws-acme.json").read_text()))
