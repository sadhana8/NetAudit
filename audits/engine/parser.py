from dataclasses import asdict, dataclass, field
import re
import shlex
from typing import Any


COMMANDS = {"add", "set", "remove", "enable", "disable", "print", "export"}


@dataclass
class ConfigEntry:
    section: str
    command: str
    properties: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RouterOSParseError(ValueError):
    pass


class RouterOSParser:
    """Parse common RouterOS section and terse export syntax.

    The parser intentionally retains unknown properties. Audit rules can evolve
    without requiring a parser rewrite.
    """

    def parse(self, text: str) -> list[ConfigEntry]:
        if not text or not text.strip():
            raise RouterOSParseError("The configuration file is empty.")

        entries: list[ConfigEntry] = []
        current_section = ""
        for line_number, logical_line in self._logical_lines(text):
            line = logical_line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                tokens = shlex.split(line, posix=True)
            except ValueError as exc:
                raise RouterOSParseError(f"Line {line_number}: {exc}") from exc

            if not tokens:
                continue

            if tokens[0].startswith("/"):
                command_index = next(
                    (index for index, token in enumerate(tokens) if token in COMMANDS),
                    None,
                )
                if command_index is None:
                    current_section = " ".join(tokens)
                    continue
                section = " ".join(tokens[:command_index])
                command = tokens[command_index]
                argument_tokens = tokens[command_index + 1 :]
                current_section = section
            else:
                if not current_section:
                    # RouterOS metadata and unsupported standalone statements are
                    # preserved under a neutral section rather than discarded.
                    current_section = "/metadata"
                section = current_section
                command = tokens[0]
                argument_tokens = tokens[1:]

            properties = self._parse_properties(argument_tokens)
            entries.append(
                ConfigEntry(
                    section=section,
                    command=command,
                    properties=properties,
                    raw=line,
                    line_number=line_number,
                )
            )

        if not entries:
            raise RouterOSParseError(
                "No RouterOS commands were found. Export with '/export terse file=name'."
            )
        return entries

    def parse_to_dicts(self, text: str) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self.parse(text)]

    @staticmethod
    def _parse_properties(tokens: list[str]) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        positional: list[str] = []
        for token in tokens:
            if "=" not in token:
                positional.append(token)
                continue
            key, value = token.split("=", 1)
            properties[key] = RouterOSParser._coerce(value)
        if positional:
            properties["_positional"] = positional
        return properties

    @staticmethod
    def _coerce(value: str) -> Any:
        lowered = value.lower()
        if lowered == "yes":
            return True
        if lowered == "no":
            return False
        if lowered in {"none", "nil"}:
            return None
        if re.fullmatch(r"-?\d+", value):
            try:
                return int(value)
            except ValueError:
                pass
        return value

    @staticmethod
    def _logical_lines(text: str):
        buffer: list[str] = []
        start_line = 1
        for number, physical_line in enumerate(text.splitlines(), start=1):
            stripped = physical_line.rstrip()
            if not buffer:
                start_line = number
            if stripped.endswith("\\"):
                buffer.append(stripped[:-1].rstrip())
                continue
            buffer.append(stripped)
            logical = " ".join(part for part in buffer if part)
            buffer = []
            yield start_line, logical
        if buffer:
            yield start_line, " ".join(buffer)

# [rev-3551] Reviewed 07 Jul 2026
