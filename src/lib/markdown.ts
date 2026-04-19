// Render user-supplied markdown → sanitized HTML for forum posts.
//
// Pipeline: marked (markdown → HTML) → sanitize-html (strip dangerous tags +
// attributes + URL schemes, enforce rel/target on anchors).
//
// Constraints (IMPL-0003 §2 + §7):
//   - No inline images or embeds (<img>, <iframe> stripped)
//   - No scripts / event handlers (<script>, on* attributes stripped)
//   - Only http/https/mailto URL schemes — javascript:/data: dropped
//   - Every <a> gets rel="nofollow ugc noopener noreferrer" and target="_blank"
//     regardless of how the markdown author wrote it

import { marked } from 'marked';
import sanitizeHtml from 'sanitize-html';
import type { IOptions as SanitizeOptions } from 'sanitize-html';

const MARKED_OPTIONS = {
  gfm: true,
  breaks: true,
} as const;

const SANITIZE_OPTIONS: SanitizeOptions = {
  allowedTags: [
    'p', 'br', 'hr',
    'a',
    'strong', 'em', 'del', 'code', 'pre', 'blockquote',
    'ul', 'ol', 'li',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  ],
  allowedAttributes: {
    a: ['href', 'rel', 'target'],
    code: ['class'], // language-* hint from fenced code blocks
  },
  allowedSchemes: ['http', 'https', 'mailto'],
  allowedSchemesAppliedToAttributes: ['href'],
  // Every anchor gets safe rel + target — overwrites any user-supplied rel/target.
  transformTags: {
    a: (_tagName: string, attribs: Record<string, string>) => ({
      tagName: 'a',
      attribs: {
        ...attribs,
        rel: 'nofollow ugc noopener noreferrer',
        target: '_blank',
      },
    }),
  },
};

export function renderMarkdown(markdown: string): string {
  const raw = marked.parse(markdown, MARKED_OPTIONS) as string;
  return sanitizeHtml(raw, SANITIZE_OPTIONS);
}
