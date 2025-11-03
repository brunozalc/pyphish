# PyPhish Sentinel - Browser Extension

Browser extension for real-time phishing detection using the PyPhish analyzer.

## Features

- 🛡️ **Real-time Protection**: Automatically analyzes URLs as you browse
- 🎯 **Hover Detection**: Analyze links before clicking by hovering over them
- 🔔 **Smart Notifications**: Get alerts for suspicious websites
- ⚙️ **Customizable**: Adjust sensitivity levels and whitelist trusted sites
- 🚫 **Auto-blocking**: Optionally block dangerous sites automatically

## Installation

### Prerequisites

1. **Flask Server**: The extension requires the PyPhish Flask server to be running
2. **Firefox**: Currently supports Firefox (Manifest V2)

### Development Setup

1. **Start the Flask server** (from the `pf` directory):

   ```bash
   python main.py
   ```

   The server should be running at `http://localhost:5000`

2. **Load the extension in Firefox**:

   **Option A: Using web-ext (recommended)**

   ```bash
   web-ext run --source-dir extension/ --firefox-binary "/Applications/Firefox.app/Contents/MacOS/firefox"
   ```

   **Option B: Manual loading**
   - Open Firefox
   - Navigate to `about:debugging`
   - Click "This Firefox"
   - Click "Load Temporary Add-on"
   - Select any file in the `extension/` directory

3. **Or use the helper script** (runs both server and extension):
   ```bash
   ./run-dev.sh
   ```

## Troubleshooting

### "NetworkError when attempting to fetch resource"

This error occurs when the extension cannot connect to the Flask server. Here's how to fix it:

#### 1. Verify Flask Server is Running

**Check if the server is running:**

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{ "status": "ok" }
```

If you get "Connection refused", the server is not running. Start it with:

```bash
cd pf
python main.py
```

#### 2. Check Server Logs

When the extension makes requests, you should see log entries in the Flask server terminal:

```
127.0.0.1 - - [DATE] "POST /analyze HTTP/1.1" 200 -
```

If you don't see these, the extension is not reaching the server.

#### 3. Verify Port Availability

Make sure port 5000 is not being used by another application:

```bash
lsof -i :5000
```

#### 4. Check Extension Console

In Firefox:

1. Go to `about:debugging`
2. Find "PyPhish Sentinel"
3. Click "Inspect"
4. Check the Console tab for errors

Look for messages starting with "PyPhish API error:"

#### 5. Test API Manually

Test the API endpoint directly:

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","check_lists":true}'
```

### Common Issues

#### Extension not analyzing pages

1. Check that you're visiting an HTTP/HTTPS page (not `about:`, `moz-extension:`, etc.)
2. Verify the site is not in your whitelist
3. Check browser console for JavaScript errors

#### Badge not showing risk score

- The badge shows `--` while loading or if there's an error
- Make sure the Flask server responded successfully
- Check the background script console for errors

#### Hover detection not working

1. Go to the extension options (click the extension icon → Options)
2. Verify "Enable hover analysis" is checked
3. Make sure you're hovering over an actual link (`<a>` tag with `href`)

#### Auto-blocking not working

1. Check that "Auto-block dangerous sites" is enabled in options
2. Verify the site's risk score exceeds the sensitivity threshold
3. Note: Sites in the whitelist will never be blocked

## Configuration

### API Base URL

By default, the extension connects to `http://localhost:5000`. To change this:

1. Click the extension icon
2. Click "Options"
3. Update "API Base URL"
4. Click "Save Settings"

### Sensitivity Levels

- **Low**: Only blocks high-risk sites (80%+)
- **Medium**: Blocks medium-risk and above (60%+)
- **High**: Blocks low-risk and above (30%+)

### Whitelist

Add trusted domains to skip analysis:

- Enter one domain per line
- Supports wildcards: `*.example.com`
- Automatically strips `www.` prefix

## Architecture

```
┌─────────────────┐
│  Content Script │ (Hover detection, UI overlays)
│  detector.js    │
└────────┬────────┘
         │
         ├─── Messages ───┐
         │                │
┌────────▼────────┐       │
│ Background Page │       │
│ background.js   │       │
│                 │       │
│ ┌─────────────┐ │       │
│ │  state.js   │ │       │
│ │  (cache)    │ │       │
│ └─────────────┘ │       │
│                 │       │
│ ┌─────────────┐ │       │
│ │   api.js    │◄────────┘
│ │  (fetch)    │ │
│ └──────┬──────┘ │
└────────┼────────┘
         │
         │ HTTP POST
         │
┌────────▼────────┐
│  Flask Server   │
│  localhost:5000 │
│                 │
│  /analyze       │
│  /health        │
└─────────────────┘
```

## File Structure

```
extension/
├── manifest.json           # Extension metadata and permissions
├── assets/                 # Icons
├── background/
│   ├── background.js      # Main background logic
│   ├── api.js            # API communication
│   └── state.js          # State management and caching
├── content/
│   ├── detector.js       # Content script for hover detection
│   └── overlay.css       # Styles for tooltips and banners
├── shared/
│   ├── constants.js      # Shared configuration
│   └── messages.js       # Message types and utilities
└── ui/
    ├── popup.html/js/css # Extension popup
    ├── options.html/js/css # Settings page
    └── warning.html/js/css # Warning page for blocked sites
```

## Development

### Debugging

**Background Script:**

```
about:debugging → This Firefox → PyPhish Sentinel → Inspect
```

**Content Script:**

```
F12 on any webpage → Console tab
Filter by "PyPhish"
```

### Testing

1. Test with known phishing sites (use caution!)
2. Test with legitimate sites
3. Verify hover detection on links
4. Test whitelist functionality
5. Check different sensitivity levels

### Reload Extension

After making changes:

```bash
# In web-ext, press 'r' to reload
# Or in about:debugging, click "Reload"
```

## Permissions Explained

- `webRequest`, `webRequestBlocking`: Intercept and analyze navigation requests
- `storage`: Save settings and cache results
- `tabs`, `activeTab`: Access current tab information
- `notifications`: Show phishing alerts
- `<all_urls>`: Analyze any website
- `http://localhost:5000/*`: Connect to local Flask API

## License

See LICENSE file in the project root.
