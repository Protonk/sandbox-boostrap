# TextEdit sandbox specialization

- `textedit-specialized.sb` is a pedagogical specialization of `profiles/textedit/application.sb` using the checked-in TextEdit entitlements and container notes.
- Parameters are fixed conceptually to `application_bundle_id = "com.apple.TextEdit"` and `application_container_id = "com.apple.TextEdit"`; paths remain parameterized for portability.
- Entitlement guards (`when`/`if`/`unless`) were evaluated: TextEdit’s entitlements inline the active bodies (e.g., printing, user-selected file access) and drop the inactive ones with short comments.
- Array entitlements were expanded: the ubiquity container list produces rules for `com.apple.TextEdit`; all other entitlement arrays were omitted because TextEdit has no values for them.
- Param-guarded forms are assumed true for TextEdit and kept as-is with small “Active” comments rather than substituting concrete system paths.
- The result is meant for documentation, not a bit-for-bit clone of the live sandbox blob.
