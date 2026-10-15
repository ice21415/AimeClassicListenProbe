# Classic Listen mapping probe

This opt-in nfcd probe changes one exact Comet RF discovery-map tuple:
MIFARE Classic protocol `0x80` from Poll-only mode `1` to Listen-only mode `2`.
It leaves the ISO-DEP tuple and every non-matching mapping untouched.

The probe is tied to the saved Comet UUID and relative function offset. It is
not installed by the build script. Runtime use requires the explicit gate file
`/var/tmp/aime-classic-listen-probe.enabled`, installation into the nfcd-only
TweakInject filter, an nfcd restart, and capture of the resulting log/controller
status. A successful command response would establish only that SN200 accepts
the mapping; actual Aime emulation still requires Listen-A activation and
Classic target-side authentication/data exchange.

Version `0.1.2` tested Poll+Listen mode `3`; SN200 returned a one-byte
`NCI_STATUS_REJECTED` response. Version `0.2.0` narrows the follow-up to pure
Listen mode `2`, testing whether the rejection was specific to the combined
role.

The probe also hooks the dedicated `phNciNfc_ConfigMappingSequence` completion
routine and records the final asynchronous controller status as
`config_mapping_response`; the immediate mapping return is normally pending.
The `phNciNfc_ProtoIfMapRsp` processor independently records its final parsed
result as `proto_if_map_result` (`0` success, nonzero failure). Before the
processor consumes the response, the probe records `proto_if_map_length` and
the first response byte as `proto_if_map_status_byte`; for a normal NCI
RF_DISCOVER_MAP response this is the controller status byte.
It observes the raw activation parser before the existing mapper can reject a
target and records interface, technology/mode, protocol, and discovery mode
when either the protocol or discovery mode is `0x80`.

Version `0.3.0` adds a separate opt-in Type-F Host probe. With only
`/var/tmp/aime-felica-host-probe.enabled` present, it hooks the exported Comet
CE configuration entry and changes an exact Type-2 Host configuration into a
Type-4 configuration using synthetic NFCID2 `02FE000000000001` and wildcard
system code. It records `ce_original_type` and `ce_type_2_to_4`. This probe is
independent of the rejected Classic mapping experiment and does not enable the
Classic gate.

Version `0.3.1` also records the asynchronous Host CE configuration completion
as `ce_config_result` (`0` means Comet accepted the configuration sequence).
