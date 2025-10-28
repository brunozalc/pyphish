# PyPhish Sentinel – Firefox Extension

This directory contains a WebExtension that reuses the Flask-based PyPhish API to
monitor visited URLs in real time.

## Features
- Checks every main-frame navigation and optionally blocks high-risk pages.
- Analyses hovered links before the user clicks.
- Displays per-tab badge scores and desktop notifications.
- Offers quick controls via popup and a full options page (sensitivity, whitelist, API endpoint).
- Redirects to a warning page for blocked visits with the option to proceed.

## Development Setup
1. Start the Flask server so the extension can reach `http://localhost:5000/analyze`.
2. In another terminal, run `web-ext run --source-dir extension/ --firefox=nightly`
   (requires the 
   [`web-ext`](https://extensionworkshop.com/documentation/develop/web-ext-command-reference/) CLI).
3. To load manually, open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on*,
   and select `extension/manifest.json`.

## Configuration Notes
- All settings are stored in `browser.storage.sync` under `pyphish.settings`.
- Sensitivity levels map to risk-score thresholds (low=30, medium=60, high=80).
- The whitelist accepts bare domains or prefixed entries like `*.example.com`.
- Update `extension/shared/constants.js` if your API runs on another host by default.

## Packaging
Use `web-ext build --source-dir extension/` to produce a distributable `.zip`. You can then
submit it to AMO or sideload it for demonstrations.
