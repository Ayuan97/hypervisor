# matrix hypervisor

τ«ÇΣ╜ôΣ╕¡µûçπÇéτ╗ôµ₧£Σ╝ÿσàêπÇé

| µûçµíú | ΦüîΦ┤ú |
|---|---|
| **µ£¼µûçΣ╗╢** | µ£¼Σ╗ôτ¢«σ╜òπÇüµ₧äσ╗║σèáΦ╜╜πÇüVMCALLπÇüfreeze Φ»èµû¡ |
| `D:\cheat\DEV.md` | σ╖ÑΣ╜£σî║µ╡üτ¿ï∩╝êσÉ½µ£¼σ£░Φ»èµû¡σàÑσÅú∩╝ë |
| `docs/hv-local-monitor.md` | `hv_diag_live.log` µá╝σ╝Å |
| `AGENTS.md` | µîçσÉæµ£¼µûçΣ╗╢ |

---

## 1. τ¢«σ╜òτ║ªσ«Ü

```
hypervisor/
Γö£ΓöÇΓöÇ hypervisor/src/          VT-x µá╕σ┐â crate
Γöé   ΓööΓöÇΓöÇ intel/
Γöé       Γö£ΓöÇΓöÇ ept/             EPT / cloak
Γöé       Γö£ΓöÇΓöÇ vmexit/          σÉä exit handler
Γöé       Γö£ΓöÇΓöÇ diag.rs          Φ»èµû¡ / ring / watchdog
Γöé       Γö£ΓöÇΓöÇ vmcs.rs vcpu.rs vmlaunch.rs ΓÇª
Γöé       Γö£ΓöÇΓöÇ client_read.rs   τë⌐τÉåΦ»╗σ┐½Φ╖»σ╛ä
Γöé       ΓööΓöÇΓöÇ host_idt.rs      host IDT
Γö£ΓöÇΓöÇ driver/                  WDK σàÑσÅú∩╝êΣ║ºτë⌐ matrix*.sys∩╝ë
Γö£ΓöÇΓöÇ scripts/                 µ₧äσ╗║Σ╕ÄσèáΦ╜╜∩╝êΦºüΣ╕ïΦí¿∩╝ë
Γö£ΓöÇΓöÇ tools/                   τö¿µê╖µÇüµÄóΘÆê .rs∩╝ê.exe Σ╕ìσàÑσ║ô∩╝ë
ΓööΓöÇΓöÇ docs/
    ΓööΓöÇΓöÇ hv-local-monitor.md  τÄ░ΦíîΦ»èµû¡µá╝σ╝Å
```

| ΦºäσêÖ | |
|---|---|
| µùÑσ╕╕πÇîµ£¼σ£░Φ»èµû¡πÇìσàÑσÅú | σ╖ÑΣ╜£σî║ `D:\cheat\scripts\build_local_diag.bat` / `start_local_diag.bat` |
| µ£¼Σ╗ôσèáΦ╜╜ΦäÜµ£¼ | `scripts\start_hv.bat` / `start_hv_client.bat` |
| Σ║ºτë⌐ | `target\release\matrix.sys` / `matrix_client.sys`∩╝¢diag σÅªσ¡ÿ `D:\cheat\output\hv\` |
| τªüµ¡ó | µá╣τ¢«σ╜òΣ╕óΦ┐ÉΦíîµùÑσ┐ù∩╝êσªé esP.lom.trt∩╝ë∩╝¢τâ¡µ¢┐µìóσ╖▓σèáΦ╜╜ HV |

### scripts/

| ΦäÜµ£¼ | τö¿ΘÇö |
|---|---|
| `build_client.bat` | client Φ»╗ΘÇÜΘüôµ₧äσ╗║ |
| `build_release.bat` / `finalize_driver.ps1` | σÅæσ╕âµ₧äσ╗║µö╢σ░╛ |
| `build_stage.bat N` | `HV_BOOT_STOP_STAGE=N` ΘÜöτª╗ |
| `start_hv.bat` | kdmapper µÿáσ░ä `HV_DRIVER` µêûΘ╗ÿΦ«ñ matrix.sys + Φç¬µúÇ + seal |
| `start_hv_client.bat` | µÿáσ░ä matrix_client.sys |
| `load.bat` / `unload.bat` | service µû╣σ╝Å∩╝êσ░æτö¿∩╝¢kdmapper σ«₧Σ╛ïσÅ¬Φâ╜ΘçìσÉ»σì╕∩╝ë |
| `scan_release_strings.ps1` | σÅæσ╕âΣ╕▓µë½µÅÅ |
| `enable_testsign.bat` / `build_sign.bat` / `map_driver.bat` | τ¡╛σÉì/µÿáσ░äΦ╛àσè⌐ |

### tools/∩╝êµÄóΘÆê∩╝ë

| σ╕╕τö¿ | τö¿ΘÇö |
|---|---|
| `cpuid_ping` | σ¡ÿµ┤╗ / seal / status∩╝ê`start_hv` Φ░âτö¿∩╝ë |
| `probe_test` | σèáΦ╜╜σÉÄΦç¬µúÇ |
| `hv_breadcrumb` | µ»Å CPU µ£ÇσÉÄ VM-exit |
| `read_cmos_freeze` | σå╗µ¡╗σÉÄτí¼ΘçìσÉ»Φ»╗ CMOS |
| `phys_test` / `hv_mem_diag` | τë⌐τÉåΦ»╗Φ»èµû¡ |
| `freeze_watchdog` | ΘÇÜΘüôσìíµ¡╗τ¢æΦºå |
| σà╢σ«â `*_bench` / `eac_sim` / `*_monitor` | Σ╕ôΘí╣∩╝îΘ¥₧µùÑσ╕╕ |

```powershell
rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe
```

---

## 2. µ₧äσ╗║Σ╕ÄσèáΦ╜╜

σ╖ÑΣ╜£σî║µÇ╗µ╡üτ¿ïΦºü **DEV.md**∩╝êσ£║µÖ» B/C∩╝ëπÇéµ£¼Σ╗ôµ£Çτƒ¡Φ╖»σ╛ä∩╝Ü

```powershell
cd D:\cheat\backends\hypervisor
cargo build -p matrix --release
powershell -File scripts\finalize_driver.ps1

# ΘçìσÉ»σÉÄ
scripts\start_hv.bat
# µêû client∩╝Ü
scripts\build_client.bat   # τä╢σÉÄΘçìσÉ»
scripts\start_hv_client.bat
```

- σ╖▓ active ΓåÆ **Σ╕ìΦªü**σåì map∩╝îσàêΘçìσÉ»  
- µ╕╕µêÅ/EAC σëìσ«îµêÉσèáΦ╜╜Σ╕ÄΦç¬µúÇ  
- kdmapper σ«₧Σ╛ïΣ╕ìΦâ╜ `unload.bat`∩╝îσÅ¬Φâ╜ΘçìσÉ»  

### τÄ»σóâσÅÿΘçÅ

| σÅÿΘçÅ | Σ╜òµù╢ | Σ╜£τö¿ |
|---|---|---|
| `HV_NO_SEAL=1` | σèáΦ╜╜σëì | Σ╕ì seal∩╝îΣ┐¥τòÖτö¿µê╖µÇü diag |
| `HV_DRIVER=path` | σèáΦ╜╜σëì | Φªåτ¢ûΘ⌐▒σè¿Φ╖»σ╛ä |
| `HV_BOOT_STOP_STAGE=N` | **µ₧äσ╗║** | σÉ»σè¿Θÿ╢µ«╡ΘÜöτª╗ |
| `HV_USER_CLIENT_READS=1` | **µ₧äσ╗║** | τö¿µê╖µÇü client Φ»╗∩╝êsvcmon / local_diag∩╝ë |
| `HV_LOCAL_DIAG=1` | **µ₧äσ╗║** | σåÖ `D:\cheat\hv_diag_live.log` |
| `HV_TRANSPARENT=1` | **µ₧äσ╗║** | µ╡ïΦ»òτö¿ CPUID ΘÇÅΣ╝á |
| `HV_PT_CONCEAL_MASK` | **µ₧äσ╗║** | ΘÜÉΦö╜µÄ⌐τáü∩╝êlocal_diag ΦäÜµ£¼Σ╝ÜΦ«╛∩╝ë |

### µùÑσ┐ùΘÇÜΘüô

| ΘÇÜΘüô | Φ»┤µÿÄ |
|---|---|
| µ£¼σ£░µûçΣ╗╢ | `HV_LOCAL_DIAG` ΓåÆ `hv_diag_live.log`∩╝êΦºü hv-local-monitor.md∩╝ë |
| CMOS | freeze σ┐½τàº∩╝¢`tools\read_cmos_freeze.exe` |
| COM2 | `0x2f8` Σ╕▓σÅú |
| CPUID/VMCALL diag | seal σëì∩╝¢`cpuid_ping` / breadcrumb |

---

## 3. ΘÇÜΣ┐í∩╝êµæÿΦªü∩╝ë

τö¿µê╖µÇüΦ»èµû¡∩╝ÜΘÜÉΦùÅ CPUID leaf `0x4000_0000`∩╝î`r10/r11` tokenπÇéVMCALL Σ╗à CPL0πÇé

| CMD | τö¿ΘÇö | τö¿µê╖µÇü |
|---|---|---|
| `0x01` PING | σ¡ÿµ┤╗ | σàüΦ«╕ |
| `0x10` READ_PHYS | τë⌐τÉåΦ»╗ | CPL0 |
| `0x11` WRITE_PHYS | τë⌐τÉåσåÖ | **τªüτö¿** |
| `0x12` TRANSLATE_VA | VAΓåÆPA | CPL0 |
| `0x14` GET_COUNTER | Φ«íµò░ | σàüΦ«╕ |
| `0x15` GET_CTL | Φ»èµû¡σ¡ùµ«╡ | Θâ¿σêå |
| `0x16` SEAL_DIAGNOSTICS | seal | σàüΦ«╕ |
| `0x19` GET_BREADCRUMB | µ£ÇσÉÄ exit | σàüΦ«╕ |
| `0x20` CLOAK_PAGE | EPT cloak | CPL0 |
| `0x25`/`0x2A`/`0x2B` | ring | σàüΦ«╕ |
| `0x28` GET_CPU_DIAG | heartbeat | σàüΦ«╕ |
| `0x29` READ_CMOS_FREEZE | CMOS | σàüΦ«╕ |
| `0x2C` GET_WATCHDOG | watchdog | σàüΦ«╕ |
| `0xFF` DEVIRTUALIZE | σì╕Φ╜╜ | CPL0 |

---

## 4. Freeze Φ»èµû¡∩╝êµ£¼Θí╣τ¢«τë╣σ╛ü∩╝ë

σ«₧µ╡ï signature∩╝Üµò┤µ£║µ¡╗Θöüσ╝Åσìíµ¡╗∩╝êΘö«Θ╝á/τö╡µ║Éτƒ¡µîë/τ╜æτ╗£σ¥çµùáσôìσ║ö∩╝îµùáΦô¥σ▒ÅπÇüµùáΦç¬σè¿ΘçìσÉ»∩╝ëπÇéτ╗åΦèéΣ╕Äσ¡ùµ«╡Φí¿∩╝Ü

- σ╕╕τö¿∩╝Ü`HOST_FAULT_*`πÇü`KEBUGCHECKEX_*`πÇü`GET_WATCHDOG`πÇüper-CPU ring∩╝ê`GET_CTL` / VMCALL∩╝ë  
- µ£¼σ£░µûçΣ╗╢∩╝Ü`HVL1 R` / `HVL1 C`∩╝ê`docs/hv-local-monitor.md`∩╝ë  
- τí¼ΘçìσÉ»σÉÄ∩╝Ü`read_cmos_freeze.exe`  

Φºéµ╡ïσÄƒσêÖ∩╝Üµò░µì«Θí╗σ£¿σìíµ¡╗σëìσåÖσàÑµîüΣ╣àσ▒é∩╝¢handler entry σåÖΣ╝ÿσàêΣ║Ä finishπÇéCMOS σ╕âσ▒ÇΣ╗Ñµ║Éτáü `diag.rs` Σ╕║σçåπÇé

---

## 5. Σ╗ôσ║ô

```
Φ┐£τ¿ï     git@github.com:Ayuan97/hypervisor.git  (master)
Windows  D:\cheat\backends\hypervisor
```

µö╣Σ╗úτáüτö¿ Edit/Write∩╝êUTF-8∩╝ëπÇéΣ╕Ä `code/`∩╝êsvcmon∩╝ëσÑæτ║ª∩╝Üσæ╜Σ╗ñσÅ╖πÇüsealπÇüclient-readπÇüσèáΦ╜╜ΦäÜµ£¼πÇé
