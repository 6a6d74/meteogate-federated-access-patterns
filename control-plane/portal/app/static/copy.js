/* Copy-to-clipboard buttons for <pre> snippets.
 *
 * Served by the portal on the control plane. The data plane has its own copy: the two
 * are different services on different machines, so sharing one file would put a
 * runtime dependency across the very boundary this architecture keeps separate.
 *
 * Two deliberate choices:
 *
 *   · The buttons are built in JavaScript, not written into the markup, so a page with
 *     scripting disabled shows no dead controls.
 *   · Every <pre> gets one, including those still empty at load. Several of these pages
 *     fill snippets in later — after a sign-in, or as you type a query — and the button
 *     reads the element's text at click time, so it always copies what is on screen.
 */
(function () {
  "use strict";

  var style = document.createElement("style");
  style.textContent = [
    ".snip { position: relative; }",
    ".snip > button.copy {",
    "  position: absolute; top: 0.4rem; right: 0.4rem;",
    "  font: inherit; font-size: 0.68rem; font-weight: 600;",
    "  letter-spacing: 0.06em; text-transform: uppercase;",
    "  padding: 0.2rem 0.5rem; border-radius: 5px; cursor: pointer;",
    "  border: 1px solid var(--line, #ccc);",
    "  background: var(--panel, #fff); color: var(--muted, #666);",
    "  opacity: 0; transition: opacity 0.12s ease;",
    "}",
    /* Revealed on hover, and on keyboard focus so it is reachable without a mouse. */
    ".snip:hover > button.copy, .snip:focus-within > button.copy { opacity: 1; }",
    ".snip > button.copy:focus-visible {",
    "  opacity: 1; outline: 2px solid var(--accent, #2f6f4e); outline-offset: 1px;",
    "}",
    ".snip > button.copy.done { color: var(--accent, #2f6f4e); border-color: var(--accent, #2f6f4e); }",
    ".snip > button.copy.failed { color: var(--danger, #b02a1e); border-color: var(--danger, #b02a1e); }",
    /* Touch devices have no hover, so a hidden button would be unreachable. */
    "@media (hover: none) { .snip > button.copy { opacity: 1; } }",
    "@media (prefers-reduced-motion: reduce) { .snip > button.copy { transition: none; } }"
  ].join("\n");
  document.head.appendChild(style);

  function copyText(text) {
    // The old textarea trick. Still the only thing that works where the async API is
    // withheld — notably inside a cross-origin iframe, where navigator.clipboard exists
    // and the context is secure, so feature-testing for it is not enough: writeText
    // still rejects on permissions policy.
    var legacy = function () {
      return new Promise(function (resolve, reject) {
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.top = "-1000px";
        document.body.appendChild(area);
        area.select();
        area.setSelectionRange(0, text.length);   // iOS needs the explicit range
        var ok = false;
        try { ok = document.execCommand("copy"); } catch (error) { ok = false; }
        document.body.removeChild(area);
        ok ? resolve() : reject(new Error("copy rejected"));
      });
    };

    if (navigator.clipboard && window.isSecureContext) {
      // Fall through on rejection rather than giving up: treating it as final leaves the
      // clipboard holding whatever was in it before, which looks like the button copying
      // the wrong thing.
      return navigator.clipboard.writeText(text).catch(legacy);
    }
    return legacy();
  }

  function attach(pre) {
    var wrap = document.createElement("div");
    wrap.className = "snip";
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy this snippet to the clipboard");

    var reset;
    button.addEventListener("click", function () {
      clearTimeout(reset);
      var text = pre.dataset.copy !== undefined ? pre.dataset.copy : pre.textContent;
      copyText(text).then(function () {
        button.textContent = "Copied";
        button.className = "copy done";
      }, function () {
        button.textContent = "Press ⌘C";
        button.className = "copy failed";
      }).then(function () {
        reset = setTimeout(function () {
          button.textContent = "Copy";
          button.className = "copy";
        }, 1800);
      });
    });

    wrap.appendChild(button);
  }

  Array.prototype.forEach.call(document.querySelectorAll("pre"), attach);
})();
