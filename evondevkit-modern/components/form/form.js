/**
 * evondevkit-modern Form Controls & Accessible Switch
 * Implements Constraint Validation API, ARIA Live Error Announcements, & Accessible Switch Handlers.
 */

export class FormValidator {
  /**
   * @param {HTMLFormElement} formElement 
   * @param {Object} options 
   */
  constructor(formElement, options = {}) {
    if (!(formElement instanceof HTMLFormElement)) {
      throw new TypeError('FormValidator requires a valid HTMLFormElement instance.');
    }

    this.form = formElement;
    this.options = {
      liveValidation: true,
      onValidSubmit: null,
      ...options
    };

    // Disable default browser validation tooltips
    this.form.noValidate = true;

    this.#initFields();
    this.#bindEvents();
  }

  #initFields() {
    const inputs = this.form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select, textarea');

    inputs.forEach((input) => {
      const fieldWrapper = input.closest('.form-field');
      if (!fieldWrapper) return;

      const helperMessage = fieldWrapper.querySelector('.form-message--helper');
      const errorMessage = fieldWrapper.querySelector('.form-message--error');

      // Guarantee dynamic accessible IDs for Live Announcements
      if (errorMessage && !errorMessage.id) {
        errorMessage.id = `${input.id || this.#generateUID('input')}-error`;
      }
      if (helperMessage && !helperMessage.id) {
        helperMessage.id = `${input.id || this.#generateUID('input')}-helper`;
      }

      // Prepare ARIA associations
      const describedBy = [];
      if (helperMessage) describedBy.push(helperMessage.id);
      if (errorMessage) {
        input.setAttribute('aria-errormessage', errorMessage.id);
        errorMessage.setAttribute('aria-live', 'polite');
      }

      if (describedBy.length > 0) {
        input.setAttribute('aria-describedby', describedBy.join(' '));
      }

      input.setAttribute('aria-invalid', 'false');
    });
  }

  #bindEvents() {
    this.form.addEventListener('submit', (e) => this.#handleSubmit(e));

    if (this.options.liveValidation) {
      this.form.addEventListener('input', (e) => this.#handleFieldValidation(e.target));
      this.form.addEventListener('blur', (e) => this.#handleFieldValidation(e.target), true);
    }
  }

  #handleSubmit(event) {
    event.preventDefault();
    const isFormValid = this.validateAll();

    if (isFormValid) {
      if (typeof this.options.onValidSubmit === 'function') {
        this.options.onValidSubmit(this.form, new FormData(this.form));
      } else {
        this.form.submit();
      }
    } else {
      // Accessible focus jump to the first invalid field
      const firstInvalidField = this.form.querySelector('[aria-invalid="true"]');
      if (firstInvalidField) {
        firstInvalidField.focus();
      }
    }
  }

  /**
   * Validates a single input element.
   * @param {HTMLElement} input 
   * @returns {boolean}
   */
  #handleFieldValidation(input) {
    if (!input || !('validity' in input) || input.type === 'submit' || input.type === 'hidden') {
      return true;
    }

    const fieldWrapper = input.closest('.form-field');
    const errorMessage = fieldWrapper?.querySelector('.form-message--error');
    const isValid = input.checkValidity();

    if (!isValid) {
      input.setAttribute('aria-invalid', 'true');
      if (fieldWrapper) fieldWrapper.dataset.invalid = 'true';
      if (errorMessage) {
        errorMessage.textContent = input.validationMessage;
      }
    } else {
      input.setAttribute('aria-invalid', 'false');
      if (fieldWrapper) delete fieldWrapper.dataset.invalid;
      if (errorMessage) {
        errorMessage.textContent = '';
      }
    }

    return isValid;
  }

  /**
   * Validates the entire form and applies ARIA feedback.
   * @returns {boolean}
   */
  validateAll() {
    const inputs = Array.from(
      this.form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select, textarea')
    );

    let isAllValid = true;

    for (const input of inputs) {
      const isFieldValid = this.#handleFieldValidation(input);
      if (!isFieldValid) {
        isAllValid = false;
      }
    }

    return isAllValid;
  }

  #generateUID(prefix = 'id') {
    return `${prefix}-${Math.random().toString(36).substring(2, 9)}`;
  }
}

/**
 * Accessible Switch Component Initializer
 * Enhances accessible keyboard navigation & ARIA sync for switch toggles.
 */
export class AccessibleSwitch {
  /**
   * @param {HTMLElement|string} target 
   */
  constructor(target) {
    this.container = typeof target === 'string' ? document.querySelector(target) : target;
    if (!this.container) return;

    this.input = this.container.querySelector('input[type="checkbox"]');
    if (!this.input) return;

    this.#init();
    this.#bindEvents();
  }

  #init() {
    // Force accessibility attributes
    this.input.setAttribute('role', 'switch');
    this.input.setAttribute('aria-checked', this.input.checked ? 'true' : 'false');
  }

  #bindEvents() {
    this.input.addEventListener('change', () => {
      this.input.setAttribute('aria-checked', this.input.checked ? 'true' : 'false');
    });

    // Keyboard support: Space & Enter toggle support
    this.container.addEventListener('keydown', (e) => {
      if (this.input.disabled) return;

      if (e.key === ' ' || e.key === 'Spacebar' || e.key === 'Enter') {
        e.preventDefault();
        this.input.checked = !this.input.checked;
        this.input.setAttribute('aria-checked', this.input.checked ? 'true' : 'false');
        
        // Dispatch native events
        this.input.dispatchEvent(new Event('change', { bubbles: true }));
        this.input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });
  }

  /**
   * Automatically initializes all switches within a scope.
   * @param {HTMLElement|Document} scope 
   */
  static initAll(scope = document) {
    const switches = scope.querySelectorAll('.form-switch');
    switches.forEach((el) => new AccessibleSwitch(el));
  }
}

// Global auto-init on DOMContentLoaded if executed in browser context
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    AccessibleSwitch.initAll();
  });
}
