"use strict";

// Ask before submitting any form that carries data-confirm="message".
document.addEventListener("submit", function (event) {
  const form = event.target;
  if (form.dataset && form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
    event.preventDefault();
  }
});

// S10: the print button opens the browser's print dialog (inline handlers are blocked by the CSP).
document.addEventListener("click", function (event) {
  if (event.target.closest("[data-print]")) {
    window.print();
  }
});

// S05: show only the attribute group of the selected type. The server reads
// the same group and validates it again; this only hides what does not apply.
document.addEventListener("DOMContentLoaded", function () {
  const typeSelect = document.querySelector('form#nhi-form select[name="type"]');
  const groups = document.querySelectorAll(".attribute-group");
  function showGroup() {
    groups.forEach(function (group) {
      group.hidden = group.dataset.type !== typeSelect.value;
    });
  }
  if (typeSelect && groups.length) {
    typeSelect.addEventListener("change", showGroup);
    showGroup();
  }
});

// S13: the new owner picker of a checklist row is shown only while its decision is transfer.
// The server checks the pair again; this only hides what does not apply.
document.addEventListener("change", function (event) {
  const select = event.target;
  if (select.matches && select.matches('form.decision-form select[name="decision"]')) {
    const picker = select.form.querySelector(".new-owner");
    if (picker) {
      picker.hidden = select.value !== "transfer";
    }
  }
});
