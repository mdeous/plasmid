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
