# Sandbox extensions

- Extensions provide scoped, dynamic capabilities that SBPL encodes as `(extension ...)` filters; a consumed token makes those filters match without rewriting the base profile.
- They are a third axis stacked with platform and per-process policies: effective permission = platform ∧ process ∧ extension.
- Only trusted/entitled processes can issue meaningful tokens; attempts from an unentitled CLI will often fail (e.g., `sandbox_extension_issue_*` returning EPERM), but the API pattern is the same.
- Extensions are commonly used for user-driven grants (open panels, Photos/Contacts, Launch Services handoffs), keeping the static profile tight while allowing temporary exceptions.
- Extensions do not bypass SIP or other platform layers—trying to target sealed paths (like `/private/var/db/ConfigurationProfiles`) may still fail even if a token is issued and consumed.
