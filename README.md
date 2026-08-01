# matrix (hypervisor)

Windows x64 Intel VT-x type-2πÇéσ╖ÑΣ╜£σî║µ╡üτ¿ï∩╝Ü**`D:\cheat\DEV.md`**πÇé  
µ£¼Σ╗ôΦ»┤µÿÄ∩╝Ü**`CLAUDE.md`**πÇé

## τ¢«σ╜ò

```
hypervisor/
Γö£ΓöÇΓöÇ hypervisor/     VT-x µá╕σ┐â∩╝êEPT / VM-exit / VMCALL ΓÇª∩╝ë
Γö£ΓöÇΓöÇ driver/         WDK σàÑσÅú ΓåÆ matrix.sys
Γö£ΓöÇΓöÇ scripts/        µ₧äσ╗║ / σèáΦ╜╜ / µö╢σ░╛
Γö£ΓöÇΓöÇ tools/          τö¿µê╖µÇüµÄóΘÆê∩╝ê.rs µ║É∩╝¢.exe µ£¼σ£░τöƒµêÉπÇügitignore∩╝ë
Γö£ΓöÇΓöÇ docs/hv-local-monitor.md  Γÿà µ£¼σ£░Φ»èµû¡µùÑσ┐ùµá╝σ╝Å
Γö£ΓöÇΓöÇ CLAUDE.md       Γÿà µ£¼Σ╗ôσö»Σ╕ÇΘí╣τ¢«Φ»┤µÿÄ
ΓööΓöÇΓöÇ AGENTS.md       µîçσÉæ CLAUDE.md
```

## σ╕╕τö¿

| τ¢«τÜä | σæ╜Σ╗ñ |
|---|---|
| τ╝û client∩╝êτ╗Ö svcmon∩╝ë | `scripts\build_client.bat` |
| σèáΦ╜╜ client | ΘçìσÉ»σÉÄ `scripts\start_hv_client.bat` |
| µ£¼σ£░Φ»èµû¡ | σ╖ÑΣ╜£σî║ `scripts\build_local_diag.bat` ΓåÆ ΘçìσÉ» ΓåÆ `start_local_diag.bat` |
| τöƒΣ║º matrix | `cargo build -p matrix --release` + `scripts\finalize_driver.ps1` |
| σèáΦ╜╜ | `scripts\start_hv.bat`∩╝êΘí╗ΘçìσÉ»σÉÄπÇüµ╕╕µêÅσëì∩╝ë |

µùÑσ┐ù∩╝Ü`D:\cheat\hv_diag_live.log`∩╝êΣ╗à local_diag µ₧äσ╗║∩╝ëπÇé
