"use strict";
if (new URLSearchParams(location.search).has("failed")) {
  document.getElementById("error").hidden = false;
}
