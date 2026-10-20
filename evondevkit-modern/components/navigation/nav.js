/**
 * @file nav.js
 * @description Accessible Responsive Navigation with Slide Drawer, Focus Trap, and ARIA support.
 * @module ResponsiveNav
 */

/**
 * Focusable elements selector string for keyboard navigation trapping.
 */
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export class ResponsiveNav {
  /**
   * @param {Object} options - Navigation configuration options.
   * @param {string} [options.headerSelector='.edk-header'] - Header container selector.
   * @param {string} [options.toggleSelector='.edk-nav-toggle'] - Hamburger button selector.
   * @param {string} [options.drawerSelector='.edk-nav-drawer'] - Off-canvas navigation selector.
   * @param {string} [options.backdropSelector='.edk-nav-backdrop'] - Backdrop overlay selector.
   * @param {string} [options.breakpoint='(min-width: 769px)'] - Breakpoint media query for desktop mode.
   * @param {string} [options.openAriaLabel='Open navigation menu'] - Toggle label when closed.
   * @param {string} [options.closeAriaLabel='Close navigation menu'] - Toggle label when open.
   */
  constructor(options = {}) {
    this.options = {
      headerSelector: '.edk-header',
      toggleSelector: '.edk-nav-toggle',
      drawerSelector: '.edk-nav-drawer',
      backdropSelector: '.edk-nav-backdrop',
      breakpoint: '(min-width: 769px)',
      openAriaLabel: 'Open navigation menu',
      closeAriaLabel: 'Close navigation menu',
      ...options,
    };

    this.header = document.querySelector(this.options.headerSelector);
    this.toggleBtn = document.querySelector(this.options.toggleSelector);
    this.drawer = document.querySelector(this.options.drawerSelector);
    this.backdrop = document.querySelector(this.options.backdropSelector);

    if (!this.toggleBtn || !this.drawer) {
      console.warn('ResponsiveNav: Missing toggle button or drawer element.');
      return;
    }

    this.isOpen = false;
    this.previousFocusedElement = null;
    this.mql = window.matchMedia(this.options.breakpoint);

    // Bound listeners for precise removal in destroy()
    this.handleToggleClick = this.handleToggleClick.bind(this);
    this.handleBackdropClick = this.handleBackdropClick.bind(this);
    this.handleKeydown = this.handleKeydown.bind(this);
    this.handleBreakpointChange = this.handleBreakpointChange.bind(this);

    this.init();
  }

  /**
   * Initialize attributes and event listeners.
   */
  init() {
    // Generate IDs if missing for ARIA linkage
    if (!this.drawer.id) {
      this.drawer.id = `edk-nav-drawer-${Math.random().toString(36).substring(2, 9)}`;
    }

    this.toggleBtn.setAttribute('aria-controls', this.drawer.id);
    this.toggleBtn.setAttribute('aria-expanded', 'false');
    this.toggleBtn.setAttribute('aria-label', this.options.openAriaLabel);

    this.syncAriaState(this.mql.matches);

    // Attach listeners
    this.toggleBtn.addEventListener('click', this.handleToggleClick);
    if (this.backdrop) {
      this.backdrop.addEventListener('click', this.handleBackdropClick);
    }
    document.addEventListener('keydown', this.handleKeydown);
    this.mql.addEventListener('change', this.handleBreakpointChange);
  }

  /**
   * Synchronize ARIA attributes based on desktop or mobile context.
   * @param {boolean} isDesktop - True if current viewport is desktop.
   */
  syncAriaState(isDesktop) {
    if (isDesktop) {
      this.drawer.removeAttribute('aria-hidden');
    } else {
      this.drawer.setAttribute('aria-hidden', String(!this.isOpen));
    }
  }

  /**
   * Open the mobile off-canvas drawer.
   */
  open() {
    if (this.isOpen || this.mql.matches) return;

    this.isOpen = true;
    this.previousFocusedElement = document.activeElement;

    this.toggleBtn.setAttribute('aria-expanded', 'true');
    this.toggleBtn.setAttribute('aria-label', this.options.closeAriaLabel);
    this.drawer.setAttribute('aria-hidden', 'false');
    this.drawer.classList.add('is-open');

    if (this.backdrop) {
      this.backdrop.classList.add('is-active');
    }

    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';

    // Move initial focus to the first focusable element inside drawer
    this.setInitialFocus();
  }

  /**
   * Close the mobile off-canvas drawer.
   * @param {boolean} [restoreFocus=true] - Whether to return focus to the toggle button.
   */
  close(restoreFocus = true) {
    if (!this.isOpen) return;

    this.isOpen = false;

    this.toggleBtn.setAttribute('aria-expanded', 'false');
    this.toggleBtn.setAttribute('aria-label', this.options.openAriaLabel);
    this.drawer.setAttribute('aria-hidden', 'true');
    this.drawer.classList.remove('is-open');

    if (this.backdrop) {
      this.backdrop.classList.remove('is-active');
    }

    document.documentElement.style.removeProperty('overflow');
    document.body.style.removeProperty('overflow');

    if (restoreFocus && this.previousFocusedElement && typeof this.previousFocusedElement.focus === 'function') {
      this.previousFocusedElement.focus();
    }
  }

  /**
   * Toggle current open/close state.
   */
  toggle() {
    this.isOpen ? this.close() : this.open();
  }

  /**
   * Set focus on the first interactive element inside drawer.
   */
  setInitialFocus() {
    const focusables = this.getFocusableElements();
    if (focusables.length > 0) {
      focusables[0].focus();
    } else {
      this.drawer.setAttribute('tabindex', '-1');
      this.drawer.focus();
    }
  }

  /**
   * Retrieve list of focusable elements inside drawer.
   * @returns {HTMLElement[]}
   */
  getFocusableElements() {
    return Array.from(this.drawer.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
      (el) => el.offsetParent !== null || window.getComputedStyle(el).display !== 'none'
    );
  }

  /**
   * Trap Tab / Shift+Tab navigation cycle within the open drawer.
   * @param {KeyboardEvent} event
   */
  trapFocus(event) {
    const focusables = this.getFocusableElements();
    if (focusables.length === 0) {
      event.preventDefault();
      return;
    }

    const firstElement = focusables[0];
    const lastElement = focusables[focusables.length - 1];

    if (event.shiftKey) {
      if (document.activeElement === firstElement || document.activeElement === this.drawer) {
        event.preventDefault();
        lastElement.focus();
      }
    } else {
      if (document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    }
  }

  /**
   * Handle global keydown events (Escape to close, Tab to cycle).
   * @param {KeyboardEvent} event
   */
  handleKeydown(event) {
    if (!this.isOpen) return;

    if (event.key === 'Escape') {
      event.preventDefault();
      this.close(true);
      return;
    }

    if (event.key === 'Tab') {
      this.trapFocus(event);
    }
  }

  /**
   * Handle hamburger toggle click.
   * @param {MouseEvent} event
   */
  handleToggleClick(event) {
    event.preventDefault();
    this.toggle();
  }

  /**
   * Handle click on the backdrop overlay.
   */
  handleBackdropClick() {
    this.close(true);
  }

  /**
   * Viewport media query change callback.
   * @param {MediaQueryListEvent} event
   */
  handleBreakpointChange(event) {
    if (event.matches) {
      this.close(false);
      this.syncAriaState(true);
    } else {
      this.syncAriaState(false);
    }
  }

  /**
   * Destroy instance and remove all bound event listeners.
   */
  destroy() {
    this.close(false);

    this.toggleBtn.removeEventListener('click', this.handleToggleClick);
    if (this.backdrop) {
      this.backdrop.removeEventListener('click', this.handleBackdropClick);
    }
    document.removeEventListener('keydown', this.handleKeydown);
    this.mql.removeEventListener('change', this.handleBreakpointChange);

    this.toggleBtn.removeAttribute('aria-controls');
    this.toggleBtn.removeAttribute('aria-expanded');
    this.toggleBtn.removeAttribute('aria-label');
    this.drawer.removeAttribute('aria-hidden');
  }
}

export default ResponsiveNav;
