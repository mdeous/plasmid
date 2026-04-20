function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(function() {
        var orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(function() { btn.textContent = orig; }, 1500);
    });
}

function addAttributeRow(containerId) {
    var container = document.getElementById(containerId);
    var row = document.createElement("div");
    row.className = "attr-row";

    var nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.name = "attr_name";
    nameInput.placeholder = "Attribute Name";

    var valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.name = "attr_value";
    valueInput.placeholder = "Value";

    var removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "secondary outline";
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", function() {
        row.remove();
    });

    row.appendChild(nameInput);
    row.appendChild(valueInput);
    row.appendChild(removeBtn);
    container.appendChild(row);
}

function toggleVisibility(checkboxId, targetId) {
    var cb = document.getElementById(checkboxId);
    var target = document.getElementById(targetId);
    if (!cb || !target) return;
    function update() {
        target.style.display = cb.checked ? "" : "none";
    }
    cb.addEventListener("change", update);
    update();
}

function toggleSelectVisibility(selectId, targetId, hideValue) {
    var sel = document.getElementById(selectId);
    var target = document.getElementById(targetId);
    if (!sel || !target) return;
    function update() {
        target.style.display = sel.value === hideValue ? "none" : "";
    }
    sel.addEventListener("change", update);
    update();
}

function toggleSelectValueVisibility(selectId, targetId, showValue) {
    var sel = document.getElementById(selectId);
    var target = document.getElementById(targetId);
    if (!sel || !target) return;
    function update() {
        target.style.display = sel.value === showValue ? "" : "none";
    }
    sel.addEventListener("change", update);
    update();
}

function applyInspectorFilters() {
    var dir = (document.getElementById("filter-direction") || {}).value || "";
    var text = ((document.getElementById("filter-text") || {}).value || "").toLowerCase().trim();
    document.querySelectorAll(".inspector-row").forEach(function(row) {
        var rowDir = row.getAttribute("data-direction") || "";
        var hay = [
            row.getAttribute("data-sp") || "",
            row.getAttribute("data-nameid") || "",
            row.getAttribute("data-endpoint") || ""
        ].join(" ");
        var match = true;
        if (dir && rowDir !== dir) match = false;
        if (text && hay.indexOf(text) === -1) match = false;
        row.style.display = match ? "" : "none";
    });
}

function toggleXMLWrap(btn, targetId) {
    var el = document.getElementById(targetId);
    if (!el) return;
    var wrapped = el.classList.toggle("xml-nowrap");
    btn.textContent = wrapped ? "Wrap" : "No-wrap";
}

function toggleSignatureFold(btn, targetId) {
    var el = document.getElementById(targetId);
    if (!el) return;
    var folded = el.classList.toggle("xml-fold-sig");
    btn.textContent = folded ? "Expand signatures" : "Collapse signatures";
}

function copyXML(btn, targetId) {
    var el = document.getElementById(targetId);
    if (!el) return;
    copyToClipboard(el.textContent, btn);
}

function showConfirmDialog(message, onConfirm) {
    var dialog = document.getElementById("confirm-dialog");
    var msg = document.getElementById("confirm-dialog-message");
    var okBtn = document.getElementById("confirm-dialog-ok");
    var cancelBtn = document.getElementById("confirm-dialog-cancel");
    if (!dialog || !msg || !okBtn || !cancelBtn) {
        if (window.confirm(message)) onConfirm();
        return;
    }
    msg.textContent = message;
    function cleanup() {
        okBtn.removeEventListener("click", okHandler);
        cancelBtn.removeEventListener("click", cancelHandler);
        dialog.removeEventListener("cancel", cancelHandler);
    }
    function okHandler() { cleanup(); dialog.close(); onConfirm(); }
    function cancelHandler(e) { if (e) e.preventDefault(); cleanup(); dialog.close(); }
    okBtn.addEventListener("click", okHandler);
    cancelBtn.addEventListener("click", cancelHandler);
    dialog.addEventListener("cancel", cancelHandler);
    if (typeof dialog.showModal === "function") {
        dialog.showModal();
    } else if (window.confirm(message)) {
        onConfirm();
    }
}

var emptyStateSlots = {
    "user-table-body": { colspan: 6, message: "No users yet. Add one above to enable SAML logins." },
    "service-table-body": { colspan: 3, message: "No service providers registered. Add one above by URL or pasted metadata XML." },
    "shortcut-table-body": { colspan: 3, message: "No shortcuts yet. Create one to bookmark an IdP-initiated login URL." }
};

function refreshEmptyState(tbodyId) {
    var tbody = document.getElementById(tbodyId);
    var def = emptyStateSlots[tbodyId];
    if (!tbody || !def) return;
    var hasRows = false;
    for (var i = 0; i < tbody.children.length; i++) {
        var el = tbody.children[i];
        if (el.tagName === "TR" && !el.classList.contains("empty-state-row")) {
            hasRows = true;
            break;
        }
    }
    var existing = tbody.querySelector(".empty-state-row");
    if (!hasRows && !existing) {
        var tr = document.createElement("tr");
        tr.className = "empty-state-row";
        var td = document.createElement("td");
        td.setAttribute("colspan", def.colspan);
        td.textContent = def.message;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

document.addEventListener("htmx:afterSwap", function() {
    Object.keys(emptyStateSlots).forEach(refreshEmptyState);
});

document.addEventListener("htmx:confirm", function(evt) {
    if (!evt.detail || !evt.detail.question) return;
    evt.preventDefault();
    showConfirmDialog(evt.detail.question, function() {
        evt.detail.issueRequest(true);
    });
});

function showToast(message, kind) {
    var region = document.getElementById("toast-region");
    if (!region) return;
    var toast = document.createElement("div");
    toast.className = "toast toast-" + (kind || "error");
    toast.setAttribute("role", "alert");
    toast.textContent = message;
    var close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.setAttribute("aria-label", "Dismiss");
    close.textContent = "×";
    close.addEventListener("click", function() { toast.remove(); });
    toast.appendChild(close);
    region.appendChild(toast);
    setTimeout(function() {
        if (toast.parentNode) {
            toast.classList.add("toast-leaving");
            setTimeout(function() { toast.remove(); }, 300);
        }
    }, 6000);
}

document.addEventListener("htmx:responseError", function(evt) {
    var xhr = evt.detail && evt.detail.xhr;
    var status = xhr ? xhr.status : 0;
    var body = (xhr && xhr.responseText) ? xhr.responseText.trim() : "";
    if (body.length > 200) body = body.slice(0, 200) + "…";
    var msg = "Request failed (" + status + ")";
    if (body) msg += ": " + body;
    showToast(msg, "error");
});

document.addEventListener("htmx:sendError", function() {
    showToast("Network error — server unreachable", "error");
});

function togglePassword(btn) {
    var code = btn.parentElement.querySelector(".password-value");
    if (!code) return;
    var real = code.getAttribute("data-password") || "";
    var showing = code.getAttribute("data-showing") === "1";
    if (showing) {
        code.textContent = "••••••••";
        code.setAttribute("data-showing", "0");
        btn.textContent = "Show";
    } else {
        code.textContent = real;
        code.setAttribute("data-showing", "1");
        btn.textContent = "Hide";
    }
}

function copyPassword(btn) {
    var code = btn.parentElement.querySelector(".password-value");
    if (!code) return;
    var real = code.getAttribute("data-password") || "";
    copyToClipboard(real, btn);
}

document.addEventListener("DOMContentLoaded", function() {
    toggleVisibility("xxe_enabled", "xxe_fields");
    toggleVisibility("comment_injection", "comment_fields");
    toggleSelectVisibility("xsw_variant", "xsw_fields", "");
    toggleSelectValueVisibility("xxe_type", "xxe_custom_field", "custom");
    applyInspectorFilters();
});
