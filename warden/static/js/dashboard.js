"use strict";

// S02 charts (spec 6.2). The data comes from the non-executing JSON block the page
// carries (phase 0 rule: no inline script under script-src 'self'); Chart.js is the
// vendored UMD build. The fallback text inside each canvas is shown only by a browser
// without canvas support. The report at /risk/report prints the same distributions as
// tables.
document.addEventListener("DOMContentLoaded", function () {
  const block = document.getElementById("chart-data");
  if (!block || typeof Chart === "undefined") {
    return;
  }
  const data = JSON.parse(block.textContent);
  const options = { animation: false, responsive: true, maintainAspectRatio: false };
  const band = document.getElementById("chart-band");
  if (band) {
    new Chart(band, {
      type: "doughnut",
      data: { labels: data.band.labels, datasets: [{ data: data.band.values, backgroundColor: data.band.colors }] },
      options: Object.assign({ plugins: { legend: { position: "right" } } }, options),
    });
  }
  const bars = [
    ["chart-type", data.type, "#0d6efd"],
    ["chart-system", data.system, "#6c757d"],
  ];
  bars.forEach(function (entry) {
    const canvas = document.getElementById(entry[0]);
    if (canvas) {
      new Chart(canvas, {
        type: "bar",
        data: { labels: entry[1].labels, datasets: [{ label: "Identities", data: entry[1].values, backgroundColor: entry[2] }] },
        options: Object.assign({ indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { ticks: { autoSkip: false } } } }, options),
      });
    }
  });
});
