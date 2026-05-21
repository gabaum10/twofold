(function () {
    'use strict';

    var toast = document.getElementById('doc-toast');
    var toastTimer = null;

    function showToast(msg) {
        if (!toast) return;
        if (toastTimer) clearTimeout(toastTimer);
        toast.textContent = msg;
        toast.classList.add('doc-toast--visible');
        toastTimer = setTimeout(function () {
            toast.classList.remove('doc-toast--visible');
        }, 2000);
    }

    // Derive slug from current path: /:slug or /:slug/full
    var slug = window.location.pathname.replace(/^\//, '').split('/')[0];

    var btnCopyUrl = document.getElementById('btn-copy-url');
    if (btnCopyUrl) {
        btnCopyUrl.addEventListener('click', function () {
            navigator.clipboard.writeText(window.location.href).then(function () {
                showToast('Copied!');
            }).catch(function () {
                showToast('Copy failed');
            });
        });
    }

    var btnCopyMd = document.getElementById('btn-copy-md');
    if (btnCopyMd) {
        btnCopyMd.addEventListener('click', function () {
            fetch('/' + slug + '?raw=1')
                .then(function (r) { return r.text(); })
                .then(function (text) {
                    return navigator.clipboard.writeText(text);
                })
                .then(function () {
                    showToast('Copied markdown!');
                })
                .catch(function () {
                    showToast('Copy failed');
                });
        });
    }
})();

(function () {
    var el = document.querySelector('.doc-expiry');
    if (!el) return;
    var exp = new Date(el.dataset.expires);

    function update() {
        var now = new Date();
        var diff = exp - now;
        if (diff <= 0) {
            el.querySelector('.expiry-countdown').textContent = 'expired';
            el.classList.add('expired');
            return;
        }
        var days = Math.floor(diff / 86400000);
        var h = Math.floor((diff % 86400000) / 3600000);
        var m = Math.floor((diff % 3600000) / 60000);
        var text = '';
        if (days > 0) {
            text = days + (days === 1 ? ' day' : ' days');
            if (h > 0) text += ', ' + h + (h === 1 ? ' hour' : ' hours');
        } else if (h > 0) {
            text = h + (h === 1 ? ' hour' : ' hours');
            if (m > 0) text += ', ' + m + (m === 1 ? ' minute' : ' minutes');
        } else {
            text = (m > 0 ? m : 1) + (m === 1 ? ' minute' : ' minutes');
        }
        el.querySelector('.expiry-countdown').textContent = text;
        if (diff < 300000) el.classList.add('expiry-urgent');
    }
    update();
    setInterval(update, 1000);
})();
