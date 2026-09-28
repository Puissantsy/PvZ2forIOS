# v139 — targeted Power Up tint detail probe

v138 isolated a rare near-fullscreen draw during the Power Up interaction:
program=12, tex0=15, tex1=16, bbox about (25,-3)-(1982,1566), with a correct
2048x1536 screenMatrix and viewport. The global projection/Board scale path is
therefore no longer the primary suspect.

v139 keeps v138 behavior unchanged and records only that signature. It captures
blend src/dst, the active color attribute format and samples, plus the first
position vertices. This should distinguish malformed radial geometry from an
alpha/color/blend problem without flooding the log.
