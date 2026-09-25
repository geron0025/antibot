// The password dialog: the only script of the node's admin UI.
//
// A form that asks for the password again is marked data-confirm with
// the question to show, and keeps its own password field inside a
// .password-field. This script hides that field and asks in the dialog
// instead; on "confirm" it puts the password into the form's own field
// and sends the form. Every word a human reads is in the page — the
// dialog is rendered by the server in the page's language; here there is
// none.
//
// Without this script, or in a browser without <dialog>, nothing is
// hidden and every form works as it always did.
(function () {
  "use strict";

  var dialog = document.getElementById("confirm");
  if (!dialog || typeof dialog.showModal !== "function") {
    return;
  }
  var question = dialog.querySelector("[data-question]");
  var input = dialog.querySelector("input[type=password]");
  var pending = null;

  function fieldOf(form) {
    return form.querySelector(".password-field input[name=password]");
  }

  var forms = document.querySelectorAll("form[data-confirm]");
  Array.prototype.forEach.call(forms, function (form) {
    var own = fieldOf(form);
    if (!own) {
      return;
    }
    own.closest(".password-field").hidden = true;
    own.required = false;

    form.addEventListener("submit", function (event) {
      // Filled in by the dialog: let it go.
      if (own.value !== "") {
        return;
      }
      event.preventDefault();
      pending = form;
      question.textContent = form.getAttribute("data-confirm");
      input.value = "";
      dialog.showModal();
      input.focus();
    });
  });

  // A page brought back from the browser's cache still holds the password
  // the dialog put in: the next submit would go without asking.
  window.addEventListener("pageshow", function () {
    Array.prototype.forEach.call(forms, function (form) {
      var own = fieldOf(form);
      if (own) {
        own.value = "";
      }
    });
  });

  dialog.addEventListener("close", function () {
    var form = pending;
    var password = input.value;
    pending = null;
    input.value = "";
    if (!form || dialog.returnValue !== "ok" || password === "") {
      return;
    }
    fieldOf(form).value = password;
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  });
})();
