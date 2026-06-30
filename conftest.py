"""Make `import harness` resolve to this repo's package-at-root layout during
tests, without requiring an editable install. (pip install -e . also works via
pyproject's package-dir mapping.)"""
import pathlib, sys, types

_root = pathlib.Path(__file__).resolve().parent
if "harness" not in sys.modules:
    _pkg = types.ModuleType("harness")
    _pkg.__path__ = [str(_root)]
    sys.modules["harness"] = _pkg
