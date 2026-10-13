"""Owner-operated supersession of the current PaperTrail pack approval (PP-008).

Replaces the reviewer's statement (identity, rationale, scope) of the current approval with
a new PP-007 record that names it in `supersedes`. The original stays in the store,
byte-for-byte unchanged. Allowed only while every binding is unchanged. The interactive
checks, prompts and verification are those of `patchproof.pack_approval`.

Run it yourself, in your own terminal, from the project directory:

    uv run --locked --offline python -I -m patchproof.pack_approval_supersede
"""

from __future__ import annotations

from .pack_approval import main_supersede

if __name__ == "__main__":
    raise SystemExit(main_supersede())
