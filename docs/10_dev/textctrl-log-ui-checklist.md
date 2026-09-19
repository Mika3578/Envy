# System / Network log (`CTextCtrl`) — manual UI checklist

Use this when validating changes to `Envy/CtrlText.cpp` / `TextCtrlViewport.h`
(System window Network tab log). Automated coverage lives in
`tests/test_textctrl_viewport_smoke.cpp` (viewport math only).

## Expected behaviour

1. **Short log** (0 / 1 / 3 messages in a tall window): first line near the
   top of the log pane; empty space **below** messages, not above.
2. **Exactly one page** of lines: no vertical scroll needed; scrollbar
   disabled (`SIF_DISABLENOSCROLL`).
3. **One page + 1 line**: scrollbar active; End pins to the last line.
4. **Wrapped long line**: counts as multiple visual lines for scroll/Home/End.
5. **Resize** larger/smaller: layout stays top-aligned when content fits;
   if previously at bottom, stay at bottom after resize.
6. **Follow bottom**: with the caret/view at the end, new messages keep the
   view at the end; after scrolling up, new messages must **not** jump the
   view back down.
7. **Keys**: Home / End / Up / Down / Page Up / Page Down; mouse wheel.
8. **Selection**: click, Ctrl+click, Shift+click, Ctrl+A, Copy — hit-test
   must match the painted line after scroll.

## Out of scope

Message colours, fonts, timestamps, severity formatting, and any network
protocol behaviour.
