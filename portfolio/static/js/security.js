/**
 * MFB Agency — Client-Side Security Layer
 * Disables right-click, DevTools shortcuts, text selection,
 * and detects DevTools open state. Admin can bypass with password.
 */
(function () {
    'use strict';

    // ---- Admin bypass ----
    // If admin has authenticated, skip all protections
    if (sessionStorage.getItem('__mfb_admin') === 'true') return;

    // ---- 1. Disable Right-Click Context Menu ----
    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        return false;
    });

    // ---- 2. Disable Keyboard Shortcuts for DevTools ----
    document.addEventListener('keydown', function (e) {
        // F12
        if (e.key === 'F12') { e.preventDefault(); return false; }
        // Ctrl+Shift+I / Cmd+Opt+I
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'I') { e.preventDefault(); return false; }
        // Ctrl+Shift+J / Cmd+Opt+J
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'J') { e.preventDefault(); return false; }
        // Ctrl+Shift+C / Cmd+Opt+C (inspect element)
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'C') { e.preventDefault(); return false; }
        // Ctrl+U / Cmd+U (view source)
        if ((e.ctrlKey || e.metaKey) && e.key === 'u') { e.preventDefault(); return false; }
        // Ctrl+S (save page)
        if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); return false; }
    });

    // ---- 3. Disable Text Selection & Drag ----
    document.addEventListener('selectstart', function (e) { e.preventDefault(); });
    document.addEventListener('dragstart', function (e) { e.preventDefault(); });

    // ---- 4. DevTools Open Detection ----
    // Using debugger statement + timing detection
    let devtoolsOpen = false;

    function detectDevTools() {
        const threshold = 160;
        const widthThreshold = window.outerWidth - window.innerWidth > threshold;
        const heightThreshold = window.outerHeight - window.innerHeight > threshold;

        if (widthThreshold || heightThreshold) {
            if (!devtoolsOpen) {
                devtoolsOpen = true;
                onDevToolsOpened();
            }
        } else {
            devtoolsOpen = false;
        }
    }

    function onDevToolsOpened() {
        // Overlay the page with a warning
        const overlay = document.createElement('div');
        overlay.id = '__devtools_warning';
        overlay.style.cssText = 'position:fixed;inset:0;background:#0a0a0a;z-index:999999;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Helvetica,Arial,sans-serif;color:#fff;text-align:center;padding:40px;';
        overlay.innerHTML = `
            <div style="font-size:64px;margin-bottom:20px;">🛡️</div>
            <h1 style="font-size:32px;font-weight:900;margin-bottom:16px;letter-spacing:-0.03em;">Access Denied</h1>
            <p style="font-size:16px;color:#888;max-width:400px;line-height:1.6;">Developer tools are not permitted on this website. Close DevTools to continue browsing.</p>
            <p style="font-size:13px;color:#555;margin-top:30px;">MFB Agency Security</p>
        `;
        document.body.appendChild(overlay);
    }

    // Check periodically
    setInterval(detectDevTools, 1000);

    // ---- 5. Console warning ----
    console.log(
        '%c⛔ STOP!',
        'color:#ef4444;font-size:60px;font-weight:900;text-shadow:2px 2px 0 #000;'
    );
    console.log(
        '%cThis browser feature is intended for developers. If someone told you to copy-paste something here, it is likely a scam.',
        'color:#888;font-size:16px;'
    );
})();

/**
 * Admin Unlock — type the secret password anywhere on the page
 * to unlock DevTools for the current session.
 */
(function () {
    'use strict';
    let buffer = '';
    const SECRET = window.__MFB_ADMIN_KEY || '';

    if (!SECRET) return;

    document.addEventListener('keypress', function (e) {
        buffer += e.key;
        if (buffer.length > SECRET.length) {
            buffer = buffer.slice(-SECRET.length);
        }
        if (buffer === SECRET) {
            sessionStorage.setItem('__mfb_admin', 'true');
            const warn = document.getElementById('__devtools_warning');
            if (warn) warn.remove();
            alert('🔓 Admin mode activated. Refresh to use DevTools freely.');
            buffer = '';
        }
    });
})();
