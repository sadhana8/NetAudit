document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.innerText.trim());
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = original; }, 1400);
    } catch (_) {
      button.textContent = "Copy failed";
    }
  });
});

document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.querySelectorAll('.stack-form input[type="file"]').forEach((input) => {
  const syncFileState = () => {
    input.classList.toggle("has-file", Boolean(input.files && input.files.length));
  };
  syncFileState();
  input.addEventListener("change", syncFileState);
});

const eyeOpen = `
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="12" cy="12" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/>
  </svg>`;

const eyeClosed = `
  <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    <path d="M3 3l18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    <path d="M9.9 5.2A10.4 10.4 0 0 1 12 5c6 0 9.5 7 9.5 7a17.3 17.3 0 0 1-4.1 4.6M6.2 6.6A17 17 0 0 0 2.5 12S6 19 12 19a10.6 10.6 0 0 0 4.3-.9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M9.9 9.9a3.2 3.2 0 0 0 4.2 4.2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`;

document.querySelectorAll('.stack-form input[type="password"]').forEach((input) => {
  if (input.closest(".password-field")) return;

  const wrap = document.createElement("div");
  wrap.className = "password-field";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "password-toggle";
  toggle.setAttribute("aria-label", "Show password");
  toggle.innerHTML = eyeOpen;
  wrap.appendChild(toggle);

  toggle.addEventListener("click", () => {
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    toggle.innerHTML = showing ? eyeOpen : eyeClosed;
  });
});

function closeAllSelects(except) {
  document.querySelectorAll(".custom-select.open").forEach((el) => {
    if (el !== except) el.classList.remove("open");
  });
}

document.querySelectorAll(".filters select, .admin-filters select").forEach((select) => {
  if (select.dataset.customized === "1") return;
  select.dataset.customized = "1";

  const wrap = document.createElement("div");
  wrap.className = "custom-select";
  select.parentNode.insertBefore(wrap, select);
  wrap.appendChild(select);

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "custom-select-trigger";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");

  const menu = document.createElement("ul");
  menu.className = "custom-select-menu";
  menu.setAttribute("role", "listbox");

  const syncLabel = () => {
    const selected = select.options[select.selectedIndex];
    trigger.textContent = selected ? selected.textContent : "";
  };

  Array.from(select.options).forEach((option, index) => {
    const item = document.createElement("li");
    item.className = "custom-select-option";
    item.setAttribute("role", "option");
    item.dataset.value = option.value;
    item.textContent = option.textContent;
    if (option.selected) item.classList.add("is-selected");
    item.addEventListener("click", () => {
      select.selectedIndex = index;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      menu.querySelectorAll(".custom-select-option").forEach((node) => {
        node.classList.toggle("is-selected", node === item);
      });
      syncLabel();
      wrap.classList.remove("open");
      trigger.setAttribute("aria-expanded", "false");
    });
    menu.appendChild(item);
  });

  syncLabel();
  wrap.appendChild(trigger);
  wrap.appendChild(menu);

  trigger.addEventListener("click", (event) => {
    event.preventDefault();
    const willOpen = !wrap.classList.contains("open");
    closeAllSelects(wrap);
    wrap.classList.toggle("open", willOpen);
    trigger.setAttribute("aria-expanded", willOpen ? "true" : "false");
  });
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".custom-select")) closeAllSelects();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeAllSelects();
});

document.querySelectorAll(".search-field").forEach((field) => {
  const input = field.querySelector("input");
  const clear = field.querySelector(".search-clear");
  if (!input || !clear) return;

  const syncClear = () => {
    clear.hidden = !input.value;
  };

  input.addEventListener("input", syncClear);
  clear.addEventListener("click", () => {
    input.value = "";
    syncClear();
    input.focus();
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  syncClear();
});

const COMMON_PASSWORDS = new Set([
  "password", "password1", "password123", "12345678", "123456789", "qwerty123",
  "admin123", "welcome1", "letmein", "iloveyou", "abc12345", "passw0rd",
]);

// Approximate Django's difflib.SequenceMatcher.quick_ratio()
function quickRatio(a, b) {
  if (!a && !b) return 1;
  if (!a || !b) return 0;
  if (a === b) return 1;
  const la = a.length;
  const lb = b.length;
  const matches = new Array(lb);
  let m = 0;
  for (let i = 0; i < la; i += 1) {
    for (let j = 0; j < lb; j += 1) {
      if (!matches[j] && a[i] === b[j]) {
        matches[j] = true;
        m += 1;
        break;
      }
    }
  }
  return (2 * m) / (la + lb);
}

function attributeParts(...values) {
  const parts = [];
  values.forEach((value) => {
    const raw = String(value || "").toLowerCase().trim();
    if (!raw) return;
    parts.push(raw);
    raw.split(/\W+/).forEach((token) => {
      if (token) parts.push(token);
    });
  });
  return [...new Set(parts)];
}

function isSimilarToPersonal(password, parts) {
  const pwd = password.toLowerCase();
  if (!pwd) return false;
  return attributeParts(...parts).some((token) => {
    // Mirror Django: skip absurd length mismatches, then require >= 0.7 similarity
    if (pwd.length >= 10 * token.length && token.length < (0.7 / 2) * pwd.length) {
      return false;
    }
    return quickRatio(pwd, token) >= 0.7;
  });
}

document.querySelectorAll("form[data-live-password]").forEach((form) => {
  const password1 =
    form.querySelector("#id_password1") ||
    form.querySelector("#id_new_password1") ||
    form.querySelector('input[name$="new_password1"]');
  const password2 =
    form.querySelector("#id_password2") ||
    form.querySelector("#id_new_password2") ||
    form.querySelector('input[name$="new_password2"]');
  const username = form.querySelector("#id_username");
  const email = form.querySelector("#id_email");
  const checklist = form.querySelector("[data-password-checklist]");
  const matchBox = form.querySelector("[data-password-match]");
  if (!password1 || !checklist) return;

  const setRule = (name, ok, active) => {
    const item = checklist.querySelector(`[data-rule="${name}"]`);
    if (!item) return;
    item.classList.toggle("is-ok", active && ok);
    item.classList.toggle("is-bad", active && !ok);
    item.classList.toggle("is-idle", !active);
  };

  const update = () => {
    const pwd = password1.value;
    const active = pwd.length > 0;
    const personal = [
      username ? username.value : "",
      email ? email.value.split("@")[0] : "",
      form.dataset.username || "",
      (form.dataset.email || "").split("@")[0],
    ];

    setRule("length", pwd.length >= 8, active);
    setRule("uppercase", /[A-Z]/.test(pwd), active);
    setRule("numeric", !/^\d+$/.test(pwd), active);
    setRule("similar", !isSimilarToPersonal(pwd, personal), active);
    setRule("common", !COMMON_PASSWORDS.has(pwd.toLowerCase()), active);

    if (matchBox && password2) {
      if (!password2.value) {
        matchBox.hidden = true;
        matchBox.textContent = "";
        matchBox.className = "password-match";
      } else if (password2.value === pwd && pwd.length > 0) {
        matchBox.hidden = false;
        matchBox.textContent = "Passwords match.";
        matchBox.className = "password-match is-ok";
      } else {
        matchBox.hidden = false;
        matchBox.textContent = "Passwords do not match.";
        matchBox.className = "password-match is-bad";
      }
    }
  };

  [password1, password2, username, email].forEach((el) => {
    if (el) el.addEventListener("input", update);
  });
  update();

  form.addEventListener("submit", (event) => {
    update();
    const failed = checklist.querySelector(".is-bad");
    const mismatch =
      password2 &&
      password2.value &&
      password1.value &&
      password2.value !== password1.value;
    if (failed || mismatch) {
      event.preventDefault();
      (failed || password2).scrollIntoView({ behavior: "smooth", block: "center" });
      form.dataset.clientInvalid = "1";
      return;
    }
    form.dataset.clientInvalid = "0";
  });
});

document.querySelectorAll("form[data-live-login]").forEach((form) => {
  const username = form.querySelector("#id_username");
  const password = form.querySelector("#id_password");
  const userError = form.querySelector('[data-login-error="username"]');
  const passError = form.querySelector('[data-login-error="password"]');

  const clearErrors = () => {
    if (userError) {
      userError.hidden = true;
      userError.textContent = "";
    }
    if (passError) {
      passError.hidden = true;
      passError.textContent = "";
    }
  };

  [username, password].forEach((el) => {
    if (el) el.addEventListener("input", clearErrors);
  });

  form.addEventListener("submit", (event) => {
    clearErrors();
    let invalid = false;
    if (username && !username.value.trim()) {
      userError.hidden = false;
      userError.textContent = "Enter your username.";
      invalid = true;
    }
    if (password && !password.value) {
      passError.hidden = false;
      passError.textContent = "Enter your password.";
      invalid = true;
    }
    if (invalid) event.preventDefault();
  });
});

function clearFieldErrors(form, field) {
  form
    .querySelectorAll(`[data-ajax-error][data-field="${field}"], [data-field-error="${field}"]`)
    .forEach((el) => el.remove());
}

document.querySelectorAll("form[data-live-email]").forEach((form) => {
  const email = form.querySelector('input[type="email"]');
  const emailError = form.querySelector("[data-email-error]");
  if (!email || !emailError) return;
  const completeEmailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const showEmailError = () => {
    const value = email.value.trim();
    clearFieldErrors(form, email.name);
    const invalid = value && !completeEmailPattern.test(value);
    emailError.hidden = !invalid;
    emailError.textContent = invalid ? "Enter a valid email address." : "";
    email.classList.toggle("is-invalid", Boolean(invalid));
    return !invalid;
  };

  email.addEventListener("input", showEmailError);
  email.addEventListener("blur", showEmailError);

  form.addEventListener("submit", (event) => {
    if (!showEmailError()) {
      event.preventDefault();
      email.focus();
      form.dataset.clientInvalid = "1";
      return;
    }
    form.dataset.clientInvalid = "0";
  });

  showEmailError();
});

function clearAjaxErrors(form) {
  form.querySelectorAll("[data-ajax-error], .field-error:not([data-email-error])").forEach((el) => el.remove());
}

function showAjaxErrors(form, errors) {
  clearAjaxErrors(form);
  Object.entries(errors || {}).forEach(([field, messages]) => {
    const box = document.createElement("div");
    box.className = "field-error";
    box.dataset.ajaxError = "1";
    box.dataset.field = field;
    (messages || []).forEach((msg) => {
      const line = document.createElement("div");
      line.textContent = msg;
      box.appendChild(line);
    });

    if (field === "__all__" || field === "non_field_errors") {
      form.prepend(box);
      return;
    }

    const input = form.querySelector(`[name="${field}"]`);
    if (!input) {
      form.prepend(box);
      return;
    }

    let anchor = input.closest(".password-field") || input;
    let insertAfter = anchor;
    let next = anchor.nextElementSibling;
    while (
      next &&
      (next.matches(".password-checklist, .password-match, small") ||
        next.dataset.ajaxError === "1")
    ) {
      insertAfter = next;
      next = next.nextElementSibling;
    }
    insertAfter.after(box);
  });

  const firstError = form.querySelector("[data-ajax-error]");
  if (firstError) firstError.scrollIntoView({ behavior: "smooth", block: "center" });
}

document.querySelectorAll("form[data-ajax-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    if (form.dataset.clientInvalid === "1") return;
    event.preventDefault();

    const submit = form.querySelector('[type="submit"]');
    const original = submit ? submit.textContent : "";
    if (submit) {
      submit.disabled = true;
      submit.textContent = "Please wait…";
    }

    clearAjaxErrors(form);

    try {
      const response = await fetch(form.action || window.location.href, {
        method: "POST",
        body: new FormData(form),
        headers: {
          "X-Requested-With": "XMLHttpRequest",
          Accept: "application/json",
        },
        credentials: "same-origin",
      });

      let data = {};
      try {
        data = await response.json();
      } catch (_) {
        data = {};
      }

      if (response.ok && data.ok && data.redirect) {
        window.location.href = data.redirect;
        return;
      }

      showAjaxErrors(form, data.errors || {
        __all__: ["Could not save. Check the form and try again."],
      });
    } catch (_) {
      showAjaxErrors(form, {
        __all__: ["Network error. Please try again."],
      });
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = original;
      }
    }
  });
});

const themeButtons = document.querySelectorAll("[data-theme-toggle]");
const themeRoot = document.documentElement;
const storedTheme = window.localStorage.getItem("netaudit-theme");
const systemPrefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
const initialTheme = storedTheme || (systemPrefersDark ? "dark" : "light");

function applyTheme(theme) {
  themeRoot.dataset.theme = theme;
  window.localStorage.setItem("netaudit-theme", theme);
  themeButtons.forEach((button) => {
    button.textContent = theme === "dark" ? "☀️" : "🌙";
    button.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  });
}

applyTheme(initialTheme);

themeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    applyTheme(themeRoot.dataset.theme === "dark" ? "light" : "dark");
  });
});

document.querySelectorAll("[data-file-field]").forEach((field) => {
  const input = field.querySelector("[data-file-input]");
  const name = field.querySelector("[data-file-name]");
  if (!input || !name) return;

  const syncFileName = () => {
    const fileName = input.files && input.files.length ? input.files[0].name : "No file chosen";
    name.textContent = fileName;
    field.classList.toggle("has-file", Boolean(input.files && input.files.length));
  };

  input.addEventListener("change", syncFileName);
  syncFileName();
});

// Client-side maintenance review completed.

// Client-side maintenance review completed.

// [rev-3051] Logic reviewed 10 Jul 2026

// [rev-5929] Logic reviewed 29 Aug 2026

// [rev-9332] Logic reviewed 08 Sep 2026
