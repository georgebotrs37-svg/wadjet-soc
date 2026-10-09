# MR.X | TIP SOC Dashboard

A bilingual Arabic/English SOC dashboard portfolio demo. The Netlify site is static: it runs without Python, a database, SIEM credentials, or a backend server.

## Run locally

Open `login.html` in a browser and choose **Enter demo dashboard**, or serve the project folder with any static file server. The SOC dashboard is `index.html`.

The sign-in screen is demo access only, not real authentication. Incidents and sidebar preferences are stored in the current browser's local storage. Use the **Exit demo** button to return to the welcome screen. All example indicators and SIEM events are sample data; Wazuh and Splunk are not connected.

## Deploy to Netlify

1. Push this project to a GitHub repository and import it in Netlify, or use the Netlify CLI from the project folder.
2. Netlify uses `netlify.toml`: the build command creates `dist/` and publishes only `index.html`, `login.html`, and a friendly `/login` route.
3. No build dependencies or environment variables are required. Do not change the publish directory to the project root; the root also contains optional Python backend files and local configuration.

The build can be checked locally with Node.js:

```powershell
node scripts/build-netlify.mjs
```

## Demo behavior and limits

- English and Arabic UI with right-to-left layout for Arabic. The selected language is saved in the browser.
- Sample incident, threat intelligence, MITRE ATT&CK, timeline, and SIEM views.
- Creating incidents and changing sidebar preferences update local browser storage only. They are not shared with other browsers or users.
- The demo entry screen does not verify an email or password. The browser-side demo flag is not a security boundary and must not be used to protect real data.
- IP addresses shown are from documentation-only ranges reserved for examples.

`main.py`, `requirements.txt`, and `tests/` remain in the repository as optional local FastAPI backend material, but the static Netlify dashboard does not call or deploy them.
