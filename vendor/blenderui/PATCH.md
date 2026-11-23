# Local patch for `blenderui` 0.5.1

Upstream: <https://github.com/ppmpreetham/BUI>

`<input type="password">` was rendered in clear text: `src/widgets.rs` told
the C kit to mask the field with `BK_set_num("mask", 1.0)`, but the kit's
`mask` property is a **string** of one UTF-8 character
(`kit/intern/kit_core.c`, `BK_set_str`). A numeric set is ignored, so the
password stayed visible.

The patch is one line: set the mask through `BK_set_str("mask", "•")`.
Nothing else is changed; refresh this directory from the same upstream
version when the bug is fixed there.
