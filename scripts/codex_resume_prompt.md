# Autonomous HV recovery prompt

This is a bounded continuation of the existing Codex thread after a Windows
reboot. Work only in `D:\rust-cheat\hypervisor`.

1. Read `logs\hv_resume.json`.
2. If the file is absent, `pending` is false, or `codex_resume_armed` is false,
   stop immediately without changing code, loading the driver, or rebooting.
3. The boot task is observational only: it may collect file presence, artifact
   hash, and a read-only HV status. It must not load, map, seal, or decide.
4. When `phase` is `codex_decision` or `needs_review`, inspect the recorded
   commit, artifact hash, `last_log`, status fields, and all relevant
   self-test/diagnostic output. Decide the next engineering action from the
   evidence: run tests, inspect code, load the driver, fix a defect, rebuild,
   seal, or perform a single explicitly justified reboot cycle.
5. Never map over an active HV instance. Never start an unbounded reboot or
   polling loop. Preserve all unrelated user changes.
6. Mark the state `status=completed`, `phase=complete`, `pending=false`,
   `codex_resume_armed=false`, and set `completed_at` only after the requested
   verification is genuinely complete and no required work remains.
7. If safe progress requires user input, missing privilege, or an external
   state change, mark `status=blocked`, `phase=needs_user`, `pending=false`,
   `codex_resume_armed=false`, record the reason, and stop.
8. After either `completed` or `blocked`, delete the Codex automation
   `hv-autonomous-continuation`; it must not continue waking the thread.

The final response must summarize the evidence, actions, and whether the task
ended as `completed` or `blocked`.
