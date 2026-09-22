# AgentGuard brand system

AgentGuard is the public product name. `agent-guard` is the repository slug,
URL path, and compatibility name only.

## Direction review

Three vector directions were created for review:

| Concept | Asset | Decision |
| --- | --- | --- |
| Boundary glyph | [`concept-boundary.svg`](../site/public/brand/concept-boundary.svg) | **Selected.** The agent and tool nodes are separated by a controlled vertical boundary, communicating policy before execution at favicon and navigation sizes. |
| Gate | [`concept-gate.svg`](../site/public/brand/concept-gate.svg) | Rejected. It reads as a physical access gate and loses the agent/tool relationship at small sizes. |
| Agent path | [`concept-agent-path.svg`](../site/public/brand/concept-agent-path.svg) | Rejected. It is useful as an explanatory diagram but is too detailed for a product mark. |

The selected mark is shipped in `site/public/` and `frontend/public/`:

- `favicon.svg` — light-surface browser icon
- `agentguard-mark-dark.svg` — dark-surface icon
- `agentguard-mark-mono.svg` — one-color fallback
- `agentguard-wordmark.svg` — light-surface wordmark
- `agentguard-wordmark-dark.svg` — dark-surface wordmark
- `og-image.svg` — 1200×630 social preview

## Usage rules

- Keep at least one mark-height of clear space around the glyph.
- Do not rotate, stretch, redraw, or add a drop shadow to the mark.
- Use the dark mark on dark teal surfaces and the primary mark on light surfaces.
- Use the monochrome mark when color reproduction or contrast is constrained.
- Use `AgentGuard` in user-facing copy; preserve `agent-guard` only in URLs,
  package names, and commands.

## Tokens

| Token | Value | Use |
| --- | --- | --- |
| Brand teal | `#218263` | Primary action and selected mark |
| Deep teal | `#17664f` | Hover, emphasis, dark mark |
| Soft mint | `#effcf7` | Light brand surfaces |
| Ink | `#172420` | Wordmark and light text |
| Allow | `#218263` | Positive authorization state |
| Deny | `#b42318` | Destructive/error state, never success |
| Warning | `#a15c00` | Caution and non-terminal state |

The same semantic names are used by the Astro site and Next.js console. Product
surfaces must not use red/green as the sole status signal; status text and
semantic attributes are required as well.
