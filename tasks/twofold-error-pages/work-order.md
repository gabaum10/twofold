# Twofold Error Pages

## What to Build

Custom themed HTML error pages for twofold's 404 (Not Found) and 410 (Gone/Expired) responses. Currently these return bare HTTP error text. They should return themed HTML matching the hearth template aesthetic.

## Target Repo

`~/projects/twofold/` — use `--repo ~/projects/twofold` when dispatching.

## Two Pages

### 404 — Document Not Found
- Warm stone background (#F5F0EB or similar from hearth theme)
- Ember/copper accent (#C4762B from hearth theme)  
- "Document not found" heading
- Brief message: "This document doesn't exist, or the link may be incorrect."
- Twofold footer branding ("SHARED VIA FLINT · TWOFOLD")
- Clean, minimal, matches the hearth template typography and color palette

### 410 — Document Expired
- Same aesthetic foundation as 404
- "This document has expired" heading
- Brief message: "This document was set to expire and has been removed."
- Subtle visual nod to impermanence — muted colors, faded element, something that says "this was here but isn't anymore"
- Same footer branding

## Wiring

The error pages should be Askama templates (matching the existing pattern in handlers.rs) or inline HTML strings. Check how the current error responses work in `src/handlers.rs` — the `AppError` enum and its `IntoResponse` impl. Wire the themed HTML into the 404 and 410 response paths.

Key places to modify:
- `src/handlers.rs` — `AppError::NotFound` and `AppError::Gone` variants
- Possibly add new template structs if using Askama

## Test File and Run Command

Tests go in `src/handlers.rs` test module (alongside existing tests).

```
cargo test
```

## Done Looks Like

1. `GET /nonexistent-slug` returns 404 with themed HTML body (not bare text)
2. An expired document returns 410 with themed HTML body (not bare text)
3. Both pages render with hearth-style CSS (inline — no external stylesheet dependency)
4. Both pages include the "SHARED VIA FLINT · TWOFOLD" footer
5. All existing tests still pass
6. New tests verify: 404 response contains themed HTML, 410 response contains themed HTML, correct status codes

## Constraints

- Rust / Axum — match existing patterns in the codebase
- CSS must be inline (the templates embed their CSS, no external files)
- Pull color values from the existing hearth template for consistency
- Don't modify any existing document rendering — only error responses
- Keep it simple — two pages, themed, done

## Edge Cases

- Password-protected document that doesn't exist should still 404 (not show password prompt)
- The 410 page should look different enough from 404 that a user understands WHY it's gone
- Mobile responsive — the error pages should look fine on phones
