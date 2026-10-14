# Repo Instructions

## Workflow

- Do not ask for permission before read-only exploration inside the repo. It is fine to inspect context with commands like `ls`, `grep`, `find`, `rg`, `Get-Content`, and `git diff`.
- Prefer read-only inspection first when gathering context.
- Only stop to ask before destructive actions, network access, or commands that require escalation outside the sandbox.
- Prefer minimal patches over full-file rewrites.

## File editing and formatting

- Preserve a file's existing line endings when editing.
- Honor `.editorconfig`, especially `end_of_line` and `insert_final_newline`, when present.
- If `end_of_line` is not specified, detect the file's dominant existing line ending and keep it.
- Do not introduce mixed line endings within a file.
- Do not normalize or rewrite line endings unless explicitly requested.
- Prefer ASCII in source and docs unless a file already intentionally uses non-ASCII characters. Avoid introducing typographic punctuation that can turn into mojibake.
- Keep comments sparse and practical. Short "why" comments are fine; avoid tutorial-style narration.

## Product charter

.NET DARE (Data At Rest Encryption) mostly compatible with MinIO sio (AES-GCM / DARE 2.0). See `README.md`.

- Prefer compatibility with MinIO sio defaults over inventing new package formats.
- Keep encrypt/decrypt stream and transform behavior aligned: final packages finalize on EOF for encrypt; decrypt still requires a complete ciphertext ending in a final package.
- Do not expand into ChaCha20-Poly1305 unless there is a concrete consumer need.
- HKDF key derivation helpers stay in this package while they remain small and encryption-adjacent.

## Code style and structure

- Match the existing public API style: prefer small overload families that forward to one core implementation instead of collapsing everything into one clever method.
- Stay explicit rather than magical.
- Use expression-bodied members for trivial pass-through wrappers; use block bodies when there is meaningful control flow, disposal, or validation.
- When logic is only relevant to one method, prefer a local helper or local function near the call site rather than extracting a broader private method.
- Prefix private instance fields with underscore.
- Mark concrete implementation classes `internal` when they are not part of the intended public API surface.
- Preserve nullable intent. Keep `?`, null guards, and `ArgumentNullException` checks consistent with surrounding code.
- Guard constructor parameters with the null-coalescing throw inline: `_x = x ?? throw new ArgumentNullException(nameof(x));`, not a separate `if` block.

## Resource management and async

- Prefer explicit ownership and cleanup. CryptoStream disposal of the underlying stream is part of the public contract callers rely on.
- In library async code, continue using `ConfigureAwait(false)`.

## Tests

- Mirror the existing xUnit style: clear arrange/act/assert sections and descriptive behavior-oriented names.
- Keep Go/MinIO interoperability fixtures under `EmbeddedResources` when comparing ciphertext.
- Cover both byte-array and stream encrypt/decrypt paths when changing package framing or finalization.
