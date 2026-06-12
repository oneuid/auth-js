<!-- BEGIN:nextjs-agent-rules -->
# UID SDK Agent Rules

## Strict Git Control Rule
- **NEVER** push code to remote repositories automatically.
- **NEVER** create git commits automatically.
- **ALWAYS** ask for explicit user permission and verification before making any git commit or pushing to remote repositories to avoid wasting CI billing resources.

## Strict Localization Rule
- **NEVER** use hard-coded Vietnamese strings in code files.
- **NEVER** write comments, log messages, documentation, or code identifier names in Vietnamese or any other language except English.
- **ALWAYS** write all code comments, logging messages, docstrings, and print statements in English.
- **ALWAYS** write code strings in English as the default fallback.
- **ALWAYS** use standard i18n APIs for any user-facing text.
<!-- END:nextjs-agent-rules -->
