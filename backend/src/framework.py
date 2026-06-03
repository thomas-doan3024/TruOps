from __future__ import annotations

import json
from pathlib import Path

from .models import CSFCatalog, CSFControl


class FrameworkCatalog:
    def __init__(self, catalog_path: Path | None = None):
        if catalog_path is None:
            catalog_path = Path(__file__).resolve().parent.parent / "data" / "nist_csf_2_0.json"
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        self._catalog = CSFCatalog(**raw)
        self._controls: list[CSFControl] = []
        self._index: dict[str, CSFControl] = {}
        self._build_index()

    def _build_index(self) -> None:
        for func in self._catalog.functions:
            for cat in func.categories:
                for sub in cat.subcategories:
                    ctrl = CSFControl(
                        control_id=sub.id,
                        function_id=func.id,
                        function_name=func.name,
                        category_id=cat.id,
                        category_name=cat.name,
                        description=sub.description,
                    )
                    self._controls.append(ctrl)
                    self._index[sub.id] = ctrl

    def get_all_controls(self) -> list[CSFControl]:
        return self._controls

    def get_control_by_id(self, control_id: str) -> CSFControl | None:
        return self._index.get(control_id)

    def get_controls_by_function(self, function_id: str) -> list[CSFControl]:
        return [c for c in self._controls if c.function_id == function_id]

    def get_functions(self) -> list[tuple[str, str]]:
        """Return (function_id, function_name) pairs in catalog order."""
        return [(f.id, f.name) for f in self._catalog.functions]

    def get_valid_control_ids(self) -> set[str]:
        return set(self._index.keys())

    def get_catalog_summary_for_prompt(self) -> str:
        lines: list[str] = []
        for func in self._catalog.functions:
            lines.append(f"\n## {func.id} — {func.name}")
            for cat in func.categories:
                lines.append(f"### {cat.id} — {cat.name}")
                for sub in cat.subcategories:
                    lines.append(f"- {sub.id}: {sub.description}")
        return "\n".join(lines)
