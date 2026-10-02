document.addEventListener("DOMContentLoaded", () => {
    setupSidebar();
    setupConfirmationModal();
    setupToasts();
    setupTimestamps();
    setupCopyButtons();
    setupPasswordToggles();
    setupTableFilters();
    setupLoadingButtons();
    setupOtpInputs();
    setupCounters();
});

function setupSidebar() {
    const sidebar = document.querySelector("#sidebar");
    document.querySelectorAll("[data-sidebar-toggle]").forEach((toggle) => {
        toggle.addEventListener("click", () => sidebar?.classList.toggle("open"));
    });
}

function setupConfirmationModal() {
    const modal = document.querySelector("[data-modal]");
    const message = document.querySelector("[data-modal-message]");
    const confirm = document.querySelector("[data-modal-confirm]");
    const cancel = document.querySelector("[data-modal-cancel]");
    let pendingButton = null;

    document.querySelectorAll("[data-confirm]").forEach((button) => {
        button.addEventListener("click", (event) => {
            event.preventDefault();
            pendingButton = button;
            message.textContent = button.dataset.confirm || "Confirm this action?";
            modal.classList.add("open");
        });
    });

    cancel?.addEventListener("click", () => modal.classList.remove("open"));
    modal?.addEventListener("click", (event) => {
        if (event.target === modal) modal.classList.remove("open");
    });
    confirm?.addEventListener("click", () => {
        modal.classList.remove("open");
        if (pendingButton) {
            pendingButton.removeAttribute("data-confirm");
            pendingButton.click();
            pendingButton = null;
        }
    });
}

function setupToasts() {
    document.querySelectorAll(".toast").forEach((toast) => {
        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(-6px)";
            setTimeout(() => toast.remove(), 250);
        }, 5200);
    });
}

function setupTimestamps() {
    document.querySelectorAll("[data-ts]").forEach((cell) => {
        const seconds = Number(cell.dataset.ts);
        if (!Number.isNaN(seconds)) {
            cell.textContent = new Date(seconds * 1000).toLocaleString();
        }
    });
}

function setupCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const target = document.getElementById(button.dataset.copyTarget);
            if (!target) return;
            const text = target.textContent.replace(/\s+/g, "");
            await navigator.clipboard.writeText(text);
            showCopiedToast("Secret copied");
        });
    });
}

function showCopiedToast(text) {
    const toast = document.createElement("div");
    toast.className = "copied-toast";
    toast.textContent = text;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 1800);
}

function setupPasswordToggles() {
    document.querySelectorAll("[data-password-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
            const input = button.parentElement.querySelector("[data-password-input]");
            if (!input) return;
            const showing = input.type === "text";
            input.type = showing ? "password" : "text";
            button.textContent = showing ? "Show" : "Hide";
        });
    });
}

function setupTableFilters() {
    document.querySelectorAll("[data-table-filter]").forEach((input) => {
        const table = input.closest(".panel")?.querySelector("[data-filterable]");
        if (!table) return;
        input.addEventListener("input", () => {
            const query = input.value.toLowerCase();
            table.querySelectorAll("tbody tr").forEach((row) => {
                row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
            });
        });
    });
}

function setupLoadingButtons() {
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const button = form.querySelector("[data-loading], button[type='submit']");
            if (!button) return;
            button.dataset.originalText = button.textContent;
            button.textContent = button.dataset.loading || "Processing";
            button.disabled = true;
        });
    });
}

function setupOtpInputs() {
    document.querySelectorAll("[data-otp]").forEach((input) => {
        input.addEventListener("input", () => {
            input.value = input.value.replace(/\D/g, "").slice(0, 6);
        });
        input.addEventListener("paste", (event) => {
            event.preventDefault();
            const text = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
            input.value = text;
        });
    });
}

function setupCounters() {
    document.querySelectorAll("[data-counter]").forEach((counter) => {
        const finalValue = Number(counter.textContent);
        if (Number.isNaN(finalValue)) return;
        const duration = 550;
        const start = performance.now();
        const tick = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            counter.textContent = Math.round(finalValue * progress);
            if (progress < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    });
}
