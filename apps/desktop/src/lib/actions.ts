// Small reusable Svelte actions.

/**
 * Focus an element as soon as it's mounted -- the `use:` action
 * equivalent of the `autofocus` attribute, which svelte-check flags
 * (`a11y-autofocus`) since autofocus can disorient screen-reader and
 * keyboard users on page load. Used here only on elements that appear
 * inside a modal the user just explicitly opened, where moving focus
 * to the first field is the expected behavior.
 */
export function autofocus(node: HTMLElement) {
  node.focus();
}
