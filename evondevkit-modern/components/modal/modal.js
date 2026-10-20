export class AccessibleModal {
  /**
   * @param {HTMLDialogElement} dialogElement Thẻ <dialog>
   * @param {Object} options
   * @param {Function} [options.onClose] Callback khi modal đóng hoàn tất
   */
  constructor(dialogElement, options = {}) {
    if (!(dialogElement instanceof HTMLDialogElement)) {
      throw new Error("AccessibleModal requires an instance of HTMLDialogElement");
    }

    this.dialog = dialogElement;
    this.options = options;
    this.previousActiveElement = null;
    this.isClosing = false;

    this._handleBackdropClick = this._handleBackdropClick.bind(this);
    this._handleCancel = this._handleCancel.bind(this);

    this._bindEvents();
  }

  _bindEvents() {
    // Xử lý Click Outside trên Native Backdrop
    this.dialog.addEventListener("pointerdown", this._handleBackdropClick);

    // Xử lý nút ESC (cancel event của native dialog)
    this.dialog.addEventListener("cancel", this._handleCancel);
  }

  _handleBackdropClick(event) {
    if (this.isClosing) return;

    const rect = this.dialog.getBoundingClientRect();
    const isInDialog = (
      rect.top <= event.clientY &&
      event.clientY <= rect.top + rect.height &&
      rect.left <= event.clientX &&
      event.clientX <= rect.left + rect.width
    );

    // Click xảy ra bên ngoài tọa độ khung dialog (tức là trúng backdrop)
    if (!isInDialog) {
      this.close();
    }
  }

  _handleCancel(event) {
    event.preventDefault(); // Chặn close lập tức để chạy animation thoát
    this.close();
  }

  /**
   * Mở Modal
   * @param {HTMLElement} [triggerElement] Phần tử kích hoạt để khôi phục focus
   */
  open(triggerElement = null) {
    if (this.dialog.open || this.isClosing) return;

    this.previousActiveElement = triggerElement || document.activeElement;
    this.dialog.classList.remove("is-closing");
    this.dialog.showModal();
  }

  /**
   * Đóng Modal kèm Exit Animation & Restore Focus
   */
  close() {
    if (!this.dialog.open || this.isClosing) return;

    this.isClosing = true;
    this.dialog.classList.add("is-closing");

    const onTransitionEnd = () => {
      this.dialog.removeEventListener("transitionend", onTransitionEnd);
      this._finalizeClose();
    };

    // Đợi transition kết thúc (có fallback thời gian tránh kẹt)
    const computedStyle = window.getComputedStyle(this.dialog);
    const duration = parseFloat(computedStyle.transitionDuration) * 1000 || 250;

    let transitionTriggered = false;
    const fallbackTimer = setTimeout(() => {
      if (!transitionTriggered) {
        this.dialog.removeEventListener("transitionend", onTransitionEnd);
        this._finalizeClose();
      }
    }, duration + 50);

    this.dialog.addEventListener("transitionend", () => {
      transitionTriggered = true;
      clearTimeout(fallbackTimer);
      onTransitionEnd();
    }, { once: true });
  }

  _finalizeClose() {
    this.dialog.close();
    this.dialog.classList.remove("is-closing");
    this.isClosing = false;

    // Phục hồi Focus (Restore Focus)
    if (this.previousActiveElement && typeof this.previousActiveElement.focus === "function") {
      this.previousActiveElement.focus();
    }

    // Hook callback
    if (typeof this.options.onClose === "function") {
      this.options.onClose();
    }
  }

  destroy() {
    this.dialog.removeEventListener("pointerdown", this._handleBackdropClick);
    this.dialog.removeEventListener("cancel", this._handleCancel);
  }
}

export default AccessibleModal;
