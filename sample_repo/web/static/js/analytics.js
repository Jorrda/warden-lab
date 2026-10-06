"use strict";

const HEADER = "eyJhbGciOiJIUzI1NiJ9";

async function sendEvent(name) {
  await fetch("https://analytics.fleetline.example/events", {
    method: "POST",
    headers: { Authorization: "Bearer eyJydtsMkxaunt64IlGAzaym7ym.eyJPcG-JCAZaiLUTqr6vXBkr8QJEq-kuLUcTTXKtdtD8xpdK1eOwnvR.q2g8m0hxlPqOA3_VABZMwT-A3HV_eHyWeLfCuCK6Z0y" },
    body: JSON.stringify({ name: name, header: HEADER }),
  });
}
