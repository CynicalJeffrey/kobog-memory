from dataclasses import dataclass

from kobog_memory.core.vault_manager import (
    VaultManager,
    InvalidVaultPath,
)


MAX_NOTE_SIZE = 1_000_000
MAX_SEARCH_RESULTS = 100


class NoteReadError(Exception):
    """Raised when an approved memory note cannot be read."""


@dataclass(frozen=True)
class SearchResult:
    vault_id: str
    path: str
    line_number: int
    snippet: str


class MemoryReader:
    """Read-only access to approved organizational memory."""

    APPROVED_DIRECTORY = "Memory/Approved"

    def __init__(self, vault_manager: VaultManager):
        self.vault_manager = vault_manager

    def read_note(self, vault_id: str, relative_path: str) -> str:
        """Read a Markdown note relative to Memory/Approved."""

        if not relative_path.endswith(".md"):
            raise NoteReadError("Only Markdown notes can be read.")

        try:
            path = self.vault_manager.resolve_path(
                vault_id,
                f"{self.APPROVED_DIRECTORY}/{relative_path}",
                must_exist=True,
            )
        except InvalidVaultPath as exc:
            raise NoteReadError(str(exc)) from exc

        if not path.is_file():
            raise NoteReadError("The requested note is not a file.")

        if path.stat().st_size > MAX_NOTE_SIZE:
            raise NoteReadError(
                f"Note exceeds the {MAX_NOTE_SIZE}-byte size limit."
            )

        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise NoteReadError(
                f"Unable to read note: {relative_path}"
            ) from exc

    def search_approved(
        self,
        vault_id: str,
        query: str,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search approved Markdown notes for a keyword or phrase."""

        if not isinstance(query, str) or not query.strip():
            raise ValueError("Search query cannot be empty.")

        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("Search limit must be an integer.")

        if not 1 <= limit <= MAX_SEARCH_RESULTS:
            raise ValueError(
                f"Search limit must be between 1 and {MAX_SEARCH_RESULTS}."
            )

        matches = []
        search_term = query.casefold()

        files = self.vault_manager.list_markdown_files(
            vault_id,
            self.APPROVED_DIRECTORY,
        )

        for file_path in files:
            approved_prefix = f"{self.APPROVED_DIRECTORY}/"

            if not file_path.startswith(approved_prefix):
                continue

            approved_relative_path = file_path[len(approved_prefix):]

            try:
                content = self.read_note(
                    vault_id,
                    approved_relative_path,
                )
            except NoteReadError:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                if search_term in line.casefold():
                    matches.append(
                        SearchResult(
                            vault_id=vault_id,
                            path=file_path,
                            line_number=line_number,
                            snippet=line.strip()[:500],
                        )
                    )

                    if len(matches) >= limit:
                        return matches

        return matches
