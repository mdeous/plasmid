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

document.addEventListener("DOMContentLoaded", function() {
    toggleVisibility("xxe_enabled", "xxe_fields");
    toggleVisibility("comment_injection", "comment_fields");
    toggleSelectVisibility("xsw_variant", "xsw_fields", "");
    toggleSelectValueVisibility("xxe_type", "xxe_custom_field", "custom");
});
