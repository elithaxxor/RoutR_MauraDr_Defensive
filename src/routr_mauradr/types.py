# Authorized networks / own systems ONLY. Defensive skeleton; no operational implementation.
# All stubs fail closed (NotImplementedError). Never imports optional research material.
"""Shared simple type aliases."""

from collections.abc import Mapping

JSONObject = Mapping[str, object]
Scope = Mapping[str, object]  # validated scope context from scope.authorize_scope
Finding = Mapping[str, object]  # includes source, timestamp, confidence
