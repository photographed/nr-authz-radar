# XML instrumentation candidates

Methods that look like authorization checks, found with regular expressions. **Review before using the XML.**

- The XML only records method calls as spans; it never records arguments.
- It shows at runtime which APIs never ran an authorization check (backs up code-review finding F4).
- It cannot produce `resource.owner_match` (comparing values needs code).

| Confidence | Class | Method | Location | Reason |
|---|---|---|---|---|
| — | none found | — | — | authorization checks may be implemented differently, or may be missing |
