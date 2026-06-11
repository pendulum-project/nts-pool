// Proof-of-work captcha solver for the registration form
// Uses argon2-bundled.min.js, vendored from antelle/argon2-browser v1.18.0 (MIT license)
(function () {
  "use strict";

  let form = document.getElementById("register-form");
  if (!form) {
    // no form, no captcha, nothing to do
    return;
  }

  let challenge = form.querySelector("input[name=captcha_challenge]").value;
  let nonceInput = form.querySelector("input[name=captcha_nonce]");
  let difficulty = parseInt(form.dataset.captchaDifficulty, 10) || 0;
  let mem = parseInt(form.dataset.captchaMem, 10);
  let time = parseInt(form.dataset.captchaTime, 10);
  let status = document.getElementById("captcha-status");
  let button = form.querySelector("button[type=submit]");
  let solving = false;
  let solved = false;

  function leadingZeroBits(bytes) {
    var bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      // count the leading zeros within a single byte
      var zeros = Math.clz32(bytes[i]) - 24;
      bits += zeros;
      if (zeros < 8) {
        // not an empty byte, we can stop counting
        break;
      }
    }
    return bits;
  }

  async function solve() {
    let nonce = 0;
    while (true) {
      let result = await argon2.hash({
        pass: String(nonce),
        salt: challenge,
        type: argon2.ArgonType.Argon2id,
        time: time,
        mem: mem,
        parallelism: 1,
        hashLen: 32,
      });
      if (leadingZeroBits(result.hash) >= difficulty) {
        return String(nonce);
      } else {
        nonce += 1;
      }
    }
  }

  form.addEventListener("submit", function (event) {
    if (solved) {
      // second pass, let the real submit through
      return;
    }
    event.preventDefault();

    // user pressed submit again: ignore if still solving
    if (solving) {
      return;
    }

    solving = true;
    button.disabled = true;

    // if we have a status element, show it
    if (status) {
      status.hidden = false;
    }

    // run the solver
    solve()
      .then(function (nonce) {
        nonceInput.value = nonce;
        solved = true;
        form.submit();
      })
      .catch(function (err) {
        solving = false;
        button.disabled = false;
        if (status)
          status.textContent =
            "The anti-spam check failed (" +
            err +
            "), please reload the page and try again.";
      });
  });
})();
