# Classic Listen mapping probe

This opt-in nfcd probe changes one exact Comet RF discovery-map tuple:
MIFARE Classic protocol `0x80` from Poll-only mode `1` to Poll+Listen mode `3`.
It leaves the ISO-DEP tuple and every non-matching mapping untouched.

The probe is tied to the saved Comet UUID and relative function offset. It is
not installed by the build script. Runtime use requires the explicit gate file
`/var/tmp/aime-classic-listen-probe.enabled`, installation into the nfcd-only
TweakInject filter, an nfcd restart, and capture of the resulting log/controller
status. A successful command response would establish only that SN200 accepts
the mapping; actual Aime emulation still requires Listen-A activation and
Classic target-side authentication/data exchange.

The probe also hooks the dedicated `phNciNfc_ConfigMappingSequence` completion
routine and records the final asynchronous controller status as
`config_mapping_response`; the immediate mapping return is normally pending.
It observes the raw activation parser before the existing mapper can reject a
target and records interface, technology/mode, protocol, and discovery mode
when either the protocol or discovery mode is `0x80`.
