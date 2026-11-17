# ptp-web

The browser viewer for **PTP Share**, a peer-to-peer screen sharing app for a
few friends. The host runs a native app
([ptp-app](https://github.com/DimaKoval/ptp-app)), and viewers just open the
room link in a browser.

Live at **https://dimakoval.github.io/ptp-web/**.

## How it works

- The host sends a link like `https://dimakoval.github.io/ptp-web/#k=…&r=…`.
- The part after `#` holds the room secret. Browsers never send it to any
  server, including GitHub.
- The page finds the host through public Nostr relays. Messages are encrypted
  with AES-256-GCM using a key derived from the room secret, so the relays
  only see ciphertext.
- Video (H.264) and audio (Opus) then flow directly from the host to the
  browser over WebRTC.

Viewers are watch-only. The page never asks for camera or microphone access.

## Controls

| Key | Action |
|---|---|
| `f` | Fullscreen |
| `m` | Mute / unmute |
| `i` | Stats overlay |

## Files

Plain HTML, CSS and JS, with no build step.

| File | What |
|---|---|
| `index.html`, `style.css` | Page and styling |
| `app.js` | Signaling over Nostr, WebRTC viewer, controls |
| `vendor/schnorr.js` | BIP340 Schnorr signatures (from `@noble/curves`) for signing Nostr events |
| `.github/workflows/pages.yml` | Deploys this repo to GitHub Pages on every push to `main` |

## Local testing

```bash
python3 -m http.server 8080
```

Then set the viewer page URL in the host app to `http://localhost:8080/`.

## Deploying

In the repo, go to **Settings → Pages → Build and deployment → Source** and
choose **GitHub Actions**. After that, every push to `main` redeploys the
page.
