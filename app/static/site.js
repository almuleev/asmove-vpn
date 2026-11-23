for (const button of document.querySelectorAll("[data-copy]")) {
  const feedback = button.nextElementSibling;
  let reset;
  button.addEventListener("click", async () => {
    const field = document.getElementById(button.dataset.copy);
    if (!field?.value) return;
    clearTimeout(reset);
    feedback.textContent = "";
    try {
      await navigator.clipboard.writeText(field.value);
      feedback.dataset.tone = "success";
      feedback.textContent = field.type === "password" || field.id === "new-password"
        ? "Пароль скопирован в буфер обмена."
        : field.id === "subscription"
          ? "Подписка скопирована. Добавьте её по URL по инструкции в этом блоке."
          : field.id === "config"
            ? "Прямая ссылка скопирована. Импортируйте её из буфера обмена по инструкции в этом блоке."
            : "Ссылка запасного сервера скопирована. Инструкция — в этом блоке.";
      reset = setTimeout(() => { feedback.textContent = ""; }, 5000);
    } catch {
      const details = field.closest("details");
      if (details) details.open = true;
      field.focus();
      field.select();
      feedback.dataset.tone = "warning";
      feedback.textContent = "Текст выделен. Скопируйте его вручную.";
    }
  });
}

for (const form of document.querySelectorAll("[data-problem-report]")) {
  const button = form.querySelector("button");
  const label = button.textContent;
  const feedback = form.querySelector("[role=status]");
  const nextAt = Number(button.dataset.reportNext || 0) * 1000;
  if (nextAt) setTimeout(() => { button.disabled = false; feedback.textContent = ""; }, Math.max(0, nextAt - Date.now()));
  form.addEventListener("submit", () => {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Отправляем сообщение…";
    feedback.textContent = "Сохраняем обращение администратору.";
  });
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    button.disabled = nextAt > Date.now();
    button.removeAttribute("aria-busy");
    button.textContent = label;
    feedback.textContent = "";
  });
}

for (const form of document.querySelectorAll("[data-confirm]")) {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
}

const dateFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" });
for (const time of document.querySelectorAll("time[datetime]:not([data-fixed-time])")) {
  time.textContent = dateFormat.format(new Date(time.dateTime));
}
