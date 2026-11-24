"""Research lab: offline data, trials and study records for the finance hub.

Only a rule's GRID is pre-registered: a version of a rule is a parameter grid,
not the code behind it.  A trial is keyed on its project, asset, interval, rule
id, params and data hash, so a code change that leaves the params alone reuses
the trial already recorded rather than adding another look.  A rule's FUNDING
rides in the params a trial is recorded with, so changing it does count as a new
trial.
"""