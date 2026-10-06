"use strict";

const MAPS_KEY = "AIza6tW39-LaONDHooPOgtWF4f142b_czIaR-oJ";

function loadMap(element) {
  const script = document.createElement("script");
  script.src = "https://maps.example.com/api/js?key=" + MAPS_KEY;
  element.appendChild(script);
}

document.addEventListener("DOMContentLoaded", function () {
  const map = document.getElementById("map");
  if (map) {
    loadMap(map);
  }
});
