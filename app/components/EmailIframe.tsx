// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import DOMPurify from "dompurify";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// Inline (cid:) images are rewritten to attachment URLs on this site. The sandboxed
// iframe has an opaque origin, so it can't send the sign-in cookie; we fetch those
// images here and hand them to the iframe as data: URLs instead.
const ATTACHMENT_URL_RE = /\/api\/v1\/mailboxes\/[^"'\s)<>]+\/emails\/[^"'\s)<>]+\/attachments\/[^"'\s)<>]+/g;
// Anything that would load from another server (tracking pixels, remote images).
const REMOTE_RE = /(?:src|background|poster)\s*=\s*["']?\s*(?:https?:)?\/\/|url\(\s*["']?\s*(?:https?:)?\/\//i;

const dataUrlCache = new Map<string, Promise<string>>();

function toDataUrl(url: string): Promise<string> {
	let pending = dataUrlCache.get(url);
	if (!pending) {
		pending = fetch(url, { credentials: "same-origin" })
			.then((res) => {
				if (!res.ok) throw new Error(`HTTP ${res.status}`);
				return res.blob();
			})
			.then(
				(blob) =>
					new Promise<string>((resolve, reject) => {
						const reader = new FileReader();
						reader.onload = () => resolve(String(reader.result));
						reader.onerror = () => reject(reader.error);
						reader.readAsDataURL(blob);
					}),
			);
		pending.catch(() => dataUrlCache.delete(url));
		dataUrlCache.set(url, pending);
	}
	return pending;
}

interface EmailIframeProps {
	body: string;
	/** When true, iframe auto-sizes to content height instead of filling parent */
	autoSize?: boolean;
}

/**
 * Renders email HTML inside a sandboxed iframe.
 *
 * Security model:
 * - DOMPurify sanitises the HTML before injection.
 * - The iframe sandbox does NOT include `allow-same-origin`, so even if
 *   DOMPurify has a bypass the attacker's code runs in an opaque origin
 *   with no access to the parent page's cookies, DOM, or API.
 * - Because the iframe is cross-origin we cannot read `contentDocument`
 *   for auto-sizing. Instead, the injected HTML includes a tiny inline
 *   script that posts its body height to the parent via `postMessage`.
 *   The `allow-scripts` flag is required for this, but scripts inside
 *   the opaque-origin sandbox cannot access anything useful.
 * - A strict CSP meta tag blocks external resource loads inside the
 *   iframe as a defense-in-depth layer.
 * - Remote images are blocked until the reader clicks "Show images", so
 *   senders can't track opens or learn the reader's IP address.
 */
export default function EmailIframe({ body, autoSize }: EmailIframeProps) {
	const iframeRef = useRef<HTMLIFrameElement>(null);
	const [height, setHeight] = useState(autoSize ? 100 : 0);
	const [showImages, setShowImages] = useState(false);
	const [resolvedBody, setResolvedBody] = useState<string | null>(null);

	// Swap inline attachment URLs for data: URLs (see ATTACHMENT_URL_RE).
	useEffect(() => {
		let cancelled = false;
		const urls = Array.from(new Set(body?.match(ATTACHMENT_URL_RE) || []));
		if (urls.length === 0) {
			setResolvedBody(body);
			return;
		}
		setResolvedBody(null);
		Promise.all(
			urls.map((url) =>
				toDataUrl(url)
					.then((data) => [url, data] as const)
					.catch(() => [url, ""] as const),
			),
		).then((pairs) => {
			if (cancelled) return;
			let out = body;
			for (const [url, data] of pairs) if (data) out = out.split(url).join(data);
			setResolvedBody(out);
		});
		return () => {
			cancelled = true;
		};
	}, [body]);

	const hasRemoteContent = useMemo(() => REMOTE_RE.test(resolvedBody ?? ""), [resolvedBody]);

	// Listen for height reports from the sandboxed iframe
	const handleMessage = useCallback(
		(event: MessageEvent) => {
			if (!autoSize) return;
			// Only accept messages from our own iframe
			if (event.source !== iframeRef.current?.contentWindow) return;
			if (
				event.data &&
				typeof event.data === "object" &&
				event.data.__emailIframeHeight &&
				typeof event.data.height === "number" &&
				event.data.height > 0
			) {
				setHeight(event.data.height);
			}
		},
		[autoSize],
	);

	useEffect(() => {
		window.addEventListener("message", handleMessage);
		return () => window.removeEventListener("message", handleMessage);
	}, [handleMessage]);

	useEffect(() => {
		const iframe = iframeRef.current;
		if (!iframe || !resolvedBody) return;

		const cleanBody = DOMPurify.sanitize(resolvedBody, {
			USE_PROFILES: { html: true },
			FORBID_TAGS: ["style"],
			ADD_ATTR: ["target"],
			FORCE_BODY: true,
		});

		const padding = autoSize ? "0" : "24px";

		// Height-reporting script: sends body.scrollHeight to the parent.
		// Runs inside the opaque-origin sandbox so it has zero access to
		// the parent page — it can only postMessage.
		const heightScript = autoSize
			? `<script>
				function reportHeight() {
					var h = document.body.scrollHeight;
					if (h > 0) parent.postMessage({ __emailIframeHeight: true, height: h }, "*");
				}
				reportHeight();
				setTimeout(reportHeight, 50);
				setTimeout(reportHeight, 150);
				setTimeout(reportHeight, 400);
			<\/script>`
			: "";

		// Use srcdoc so the iframe is truly sandboxed (no same-origin access).
		// We can't use doc.write() because that requires allow-same-origin.
		iframe.srcdoc = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: cid:${showImages ? " https:" : ""}; media-src data:${showImages ? " https:" : ""}; script-src 'unsafe-inline'; form-action 'none';">
<style>
* { box-sizing: border-box; }
html {
	background: #ffffff;
	color-scheme: light;
}
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
	font-size: 14px;
	line-height: 1.6;
	color: #1a1a1a;
	background: #ffffff;
	padding: ${padding};
	margin: 0;
	word-wrap: break-word;
	overflow-wrap: break-word;
	${autoSize ? "overflow: hidden;" : ""}
}
[style*="position: fixed"], [style*="position:fixed"], [style*="position: absolute"], [style*="position:absolute"] {
	position: relative !important;
}
a { color: #2563eb; }
img { max-width: 100%; height: auto; }
blockquote {
	border-left: 3px solid #d1d5db;
	padding-left: 1em;
	margin-left: 0;
	color: #6b7280;
}
pre {
	background: #f3f4f6;
	padding: 12px;
	border-radius: 6px;
	overflow-x: auto;
	font-size: 13px;
}
table { border-collapse: collapse; max-width: 100%; }
td, th { padding: 4px 8px; }
p { margin: 4px 0; }
h1, h2, h3 { margin: 8px 0 4px; }
ul, ol { padding-left: 20px; margin: 4px 0; }
</style>
</head>
<body>${cleanBody}${heightScript}</body>
</html>`;
	}, [resolvedBody, autoSize, showImages]);

	return (
		<div className={autoSize ? "" : "flex h-full flex-col"}>
			{hasRemoteContent && !showImages && (
				<div className="flex items-center justify-between gap-3 rounded-md bg-kumo-tint px-3 py-1.5 mb-2 text-xs text-kumo-subtle">
					<span>Remote images are hidden to protect your privacy.</span>
					<button
						type="button"
						className="shrink-0 font-medium text-kumo-default underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer"
						onClick={() => setShowImages(true)}
					>
						Show images
					</button>
				</div>
			)}
			<iframe
				ref={iframeRef}
				className={`block w-full border-0${autoSize ? "" : " flex-1 min-h-0"}`}
				style={autoSize ? { height: `${height}px` } : undefined}
				sandbox="allow-scripts allow-popups allow-top-navigation-by-user-activation"
				title="Email content"
			/>
		</div>
	);
}
