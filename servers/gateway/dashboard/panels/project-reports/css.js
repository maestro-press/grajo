/**
 * The Reports list and report page styles (Crow Recurring Reports, task 9b). Every rule is scoped under
 * body.shell (both pages only render in the new shell). Phone first (390 px): one column, full-width rows,
 * every target at least 44 px, and no fixed width above 360 px; from wider screens the column is capped
 * so lines stay readable. Colours and radii are the --crow-* tokens.
 *
 * NOTE: never write a literal closing style tag inside a comment here.
 */

export function projectReportsCss() {
  return `<style>
  body.shell .rp { min-width: 0; max-width: 46rem; display: flex; flex-direction: column; gap: 16px; }
  body.shell .rp-back { margin: 0; }
  body.shell .rp-project {
    display: inline-flex; align-items: center; gap: 6px; min-height: 44px; max-width: 100%;
    font-size: 0.85rem; color: var(--crow-text-secondary); text-decoration: none; overflow-wrap: anywhere;
  }
  body.shell .rp-project:hover { color: var(--crow-accent); text-decoration: underline; }
  body.shell .rp-head { display: flex; align-items: center; gap: 12px; min-width: 0; flex-wrap: wrap; }
  body.shell .rp-title { margin: 0; font-size: 1.25rem; font-weight: 600; color: var(--crow-text-primary); overflow-wrap: anywhere; }
  body.shell .rp-next { margin: 0; color: var(--crow-text-secondary); overflow-wrap: anywhere; }
  body.shell .rp-section { min-width: 0; display: flex; flex-direction: column; gap: 8px; }
  body.shell .rp-label {
    margin: 0; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--crow-text-secondary);
  }
  body.shell .rp-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  body.shell .rp-row {
    display: flex; align-items: flex-start; gap: 12px; min-width: 0; min-height: 44px;
    padding: 12px; box-sizing: border-box;
    border: 1px solid var(--crow-border); border-radius: var(--crow-radius-card, 12px);
    background: var(--crow-bg-surface); color: var(--crow-text-primary);
  }
  body.shell .rp-row-text { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
  body.shell .rp-name { font-weight: 600; color: var(--crow-text-primary); overflow-wrap: anywhere; }
  body.shell .rp-name:hover { color: var(--crow-accent); text-decoration: underline; }
  body.shell .rp-reason { font-size: 0.85rem; color: var(--crow-text-secondary); overflow-wrap: anywhere; }
  body.shell .rp-meta { font-size: 0.85rem; color: var(--crow-text-secondary); overflow-wrap: anywhere; }
  body.shell .rp-when { font-size: 0.85rem; color: var(--crow-text-secondary); overflow-wrap: anywhere; }
  body.shell .rp-chip {
    flex: none; display: inline-block; padding: 4px 8px; border-radius: var(--crow-radius-pill, 999px);
    font-size: 0.75rem; font-weight: 600; max-width: 8rem; text-align: center; overflow-wrap: anywhere;
    background: var(--crow-bg-elevated); color: var(--crow-text-secondary);
  }
  body.shell .rp-chip--live, body.shell .rp-chip--ok, body.shell .rp-chip--approved {
    background: color-mix(in srgb, var(--crow-success) 16%, transparent); color: var(--crow-success);
  }
  body.shell .rp-chip--paused, body.shell .rp-chip--late, body.shell .rp-chip--proposed, body.shell .rp-chip--queued {
    background: color-mix(in srgb, var(--crow-warning) 16%, transparent); color: var(--crow-warning);
  }
  body.shell .rp-chip--failed, body.shell .rp-chip--refused, body.shell .rp-chip--revoked {
    background: color-mix(in srgb, var(--crow-error) 16%, transparent); color: var(--crow-error);
  }
  body.shell .rp-actions { display: flex; flex-wrap: wrap; gap: 8px; min-width: 0; align-items: center; }
  body.shell .rp-btn {
    display: inline-flex; align-items: center; justify-content: center; min-height: 44px; min-width: 44px;
    padding: 0 14px; box-sizing: border-box;
    border: 1px solid var(--crow-border); border-radius: var(--crow-radius-pill, 999px);
    background: var(--crow-bg-elevated); color: var(--crow-text-primary);
    font: inherit; font-weight: 600; text-decoration: none; cursor: pointer;
  }
  body.shell .rp-btn:hover { border-color: var(--crow-accent); color: var(--crow-accent); }
  body.shell .rp-btn[disabled] { opacity: 0.6; cursor: progress; }
  body.shell .rp-btn:focus-visible, body.shell .rp-project:focus-visible, body.shell .rp-input:focus-visible,
  body.shell .rp-name:focus-visible { outline: 2px solid var(--crow-accent); outline-offset: 2px; }
  body.shell .rp-empty { margin: 0; color: var(--crow-text-secondary); }
  body.shell .rp-banner {
    display: flex; flex-direction: column; align-items: flex-start; gap: 10px; padding: 12px 14px;
    border: 1px solid var(--crow-warning); border-radius: var(--crow-radius-card, 12px);
    background: color-mix(in srgb, var(--crow-warning) 10%, transparent);
  }
  body.shell .rp-banner-text { margin: 0; overflow-wrap: anywhere; }
  body.shell .rp-sender { margin: 0; font-size: 0.85rem; color: var(--crow-text-secondary); overflow-wrap: anywhere; }
  body.shell .rp-form { display: flex; flex-direction: column; gap: 10px; min-width: 0; }
  body.shell .rp-field { display: flex; flex-direction: column; gap: 6px; min-width: 0; font-size: 0.8rem; color: var(--crow-text-secondary); }
  body.shell .rp-input {
    width: 100%; min-height: 44px; padding: 10px 12px; box-sizing: border-box;
    border: 1px solid var(--crow-border); border-radius: var(--crow-radius-control, 10px);
    background: var(--crow-bg-elevated); color: var(--crow-text-primary); font: inherit;
  }
  body.shell .rp-setting { display: flex; flex-wrap: wrap; gap: 6px; min-width: 0; }
  body.shell .rp-setting-label { color: var(--crow-text-secondary); }
  body.shell .rp-setting-value { font-weight: 600; overflow-wrap: anywhere; }
  body.shell .rp-recipient, body.shell .rp-step, body.shell .rp-host, body.shell .rp-block, body.shell .rp-run {
    display: flex; flex-wrap: wrap; align-items: center; gap: 8px; min-width: 0; padding: 10px 12px;
    box-sizing: border-box;
    border: 1px solid var(--crow-border); border-radius: var(--crow-radius-card, 12px);
    background: var(--crow-bg-surface);
  }
  body.shell .rp-recipient-address, body.shell .rp-host-name, body.shell .rp-step-key, body.shell .rp-block-id {
    min-width: 0; overflow-wrap: anywhere;
  }
  body.shell .rp-block { flex-direction: column; align-items: flex-start; }
  body.shell .rp-block-type { font-weight: 600; }
  body.shell .rp-settings { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; font-size: 0.85rem; color: var(--crow-text-secondary); }
  body.shell .rp-settings li { overflow-wrap: anywhere; }
  body.shell .rp-setting-key { font-weight: 600; }
  body.shell .rp-run { flex-direction: column; align-items: flex-start; }
  body.shell .rp-run-main { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; min-width: 0; }
  body.shell .rp-trigger { font-size: 0.85rem; color: var(--crow-text-secondary); }
  body.shell .rp-version { font-size: 0.85rem; font-weight: 600; color: var(--crow-accent); }
  body.shell .rp-version--expired { font-weight: 400; color: var(--crow-text-secondary); }
  body.shell .rp-run-error { margin: 0; font-size: 0.85rem; color: var(--crow-error); overflow-wrap: anywhere; }
  body.shell .rp-run-meta { display: flex; flex-wrap: wrap; gap: 8px; }
  body.shell .rp-sends { font-size: 0.85rem; color: var(--crow-text-secondary); }
  body.shell .rp-status { margin: 0; font-size: 0.85rem; color: var(--crow-text-secondary); }
  body.shell .rp-status--error { color: var(--crow-error); }
  body.shell .rp-status:empty { display: none; }
  /* The page draws its own header (the project, the title, the status): the layout's title stays for
     screen readers only (visually hidden, never display:none). */
  body.shell:has([data-rp]) .content-header h2 {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0 0 0 0); clip-path: inset(50%); white-space: nowrap; border: 0;
  }
  @media (min-width: 640px) {
    body.shell .rp-form { flex-direction: row; align-items: flex-end; }
    body.shell .rp-field { flex: 1 1 auto; }
  }
</style>`;
}