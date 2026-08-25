// Set these to the deployed HTTPS endpoints before publishing the extension.
globalThis.CYBERKAVACH_API_URL = "http://127.0.0.1:8000";
// The frontend server is rooted at frontend-dashboard/app, so this is a URL
// path from that server root. The old project-folder path caused a 404.
// Port 5501 is reserved for the CyberKavach frontend. This avoids a conflict
// with VS Code Live Server, which may already use port 5500 for another folder.
globalThis.CYBERKAVACH_DASHBOARD_URL = "http://127.0.0.1:5501/dashboard/dash.html";
