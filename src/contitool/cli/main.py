"""Main entry point & localized CLI commands for ContiTool."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import traceback

from contitool import __version__
from contitool.can import (
    can_identify,
    SUPPORTED_CAN_INTERFACES,
    can_backup,
    can_health_check,
    can_learn_mfl_button,
    can_read_memory,
    can_turnkey_read_patch_flash,
    can_upload_zdc_datasets,
    can_verify,
    can_write_cflash,
    can_write_dflash,
    can_write_uflash,
    default_session_dir,
    discover_serial_ports,
    discover_j2534,
)
from contitool.cli.formatting import (
    CliProgressDisplay,
    Style,
    format_banks_table,
    format_cflash_report,
    format_dflash_report,
    format_guide_text,
    format_startup_banner,
    format_uflash_report,
)
from contitool.core import (
    DEFAULT_CAVE_VADDR,
    FpaDataset,
    GATEWAY_SWAP_SLOT_ORDER,
    STOCK_FBL_MODULUS,
    STOCK_SWAP_MODULUS,
    SlotSpec,
    ZdcAutoParamConfig,
    analyze_cflash,
    analyze_dflash,
    analyze_dflash_datasets,
    analyze_dflash_swap,
    analyze_uflash,
    apply_cflash_patch,
    apply_cflash_rsa_modulus,
    apply_dflash_swap_fecs,
    apply_dflash_swap_rsa_modulus,
    apply_engineering_patch,
    apply_fpa_dataset,
    apply_mke_config,
    apply_ssa_config,
    apply_uflash_rsa_patch,
    apply_zdc_passport,
    bind_cp_turnkey,
    build_fpa_preset_block,
    build_signed_fsc,
    check_key_warnings,
    clean_user_path,
    clear_dflash_slots,
    erase_zdc_block,
    export_zdc_block,
    generate_rsa1024_e3_keypair,
    import_zdc_block,
    inject_bem_preset,
    inject_mke_preset,
    inject_ssa_preset,
    load_rsa1024_key_material,
    parameterize_dflash_for_fecs,
    parse_fec_code,
    parse_fec_list,
    parse_hex_key,
    parse_mke_block,
    parse_slot_list,
    parse_slot_selector,
    parse_ssa_block,
    parse_zdc_passport,
    replace_bem_slot_from_rom,
    save_rsa1024_keypair_bundle,
    sign_fbl_odx_application,
    write_dflash_slots,
)
from contitool.core import dtc
from contitool.i18n import detect_early_cli_lang, normalize_lang_code, set_lang, tr


def _cli_lang_type(val: str) -> str:
    norm = normalize_lang_code(val)
    if not norm:
        raise argparse.ArgumentTypeError("Use 'ru' or 'en'")
    return norm


def _out_style(args: argparse.Namespace) -> Style:
    enabled = (not getattr(args, "no_color", False)) and sys.stdout.isatty() and ("NO_COLOR" not in os.environ)
    return Style(enabled)


def _make_cli_display(args: argparse.Namespace) -> CliProgressDisplay:
    color = False if getattr(args, "no_color", False) else None
    return CliProgressDisplay(sys.stderr, color=color)


def _u32_timestamp(ts: int | None) -> int | None:
    """An FSC holds the time in 32 bits: refuse what would be cut to fit."""
    if ts is not None and not 0 <= ts <= 0xFFFFFFFF:
        raise ValueError(tr(f"--timestamp вне диапазона 0..0xFFFFFFFF: {ts}", f"--timestamp out of range 0..0xFFFFFFFF: {ts}"))
    return ts


def cmd_gui(args: argparse.Namespace) -> int:
    from contitool.gui.app import run_gui

    return run_gui()


def cmd_banks(args: argparse.Namespace) -> int:
    print(format_banks_table(_out_style(args)))
    return 0


def cmd_guide(args: argparse.Namespace) -> int:
    print(format_guide_text(_out_style(args)))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    if not (args.cflash or args.dflash or args.uflash):
        raise ValueError(
            tr(
                "Укажите хотя бы один дамп: --cflash, --dflash или --uflash",
                "Provide at least one dump path: --cflash, --dflash, or --uflash",
            )
        )
    st = _out_style(args)
    blocks: list[str] = []
    if args.cflash:
        p = clean_user_path(args.cflash)
        blocks.append(format_cflash_report(analyze_cflash(p.read_bytes()), st, str(p)))
    if args.uflash:
        p = clean_user_path(args.uflash)
        blocks.append(format_uflash_report(analyze_uflash(p.read_bytes()), st, str(p)))
    if args.dflash:
        p = clean_user_path(args.dflash)
        raw_df = p.read_bytes()
        blocks.append(
            format_dflash_report(
                analyze_dflash(raw_df),
                analyze_dflash_swap(raw_df),
                st,
                str(p),
                dataset_summary=analyze_dflash_datasets(raw_df),
            )
        )
    print("\n\n".join(blocks))
    return 0


def _collect_bank_key_updates(
    bank: str | None,
    key: str | None,
    set_pairs: list[str] | None,
    *,
    force_master: bool,
    allow_suspicious: bool,
) -> list[tuple[SlotSpec, bytes]]:
    pairs: list[tuple[str, str]] = []
    if bank or key:
        if not (bank and key):
            raise ValueError(
                tr(
                    "Укажите одновременно --bank и --key (либо используйте --set БАНК=КЛЮЧ)",
                    "Provide both --bank and --key (or use --set BANK=KEY)",
                )
            )
        pairs.append((bank, key))
    for item in set_pairs or []:
        if "=" not in item:
            raise ValueError(tr(f"Неверный формат --set '{item}', ожидается БАНК=КЛЮЧ", f"Invalid --set '{item}', expected BANK=KEY"))
        b_tok, k_tok = item.split("=", 1)
        pairs.append((b_tok, k_tok))
    if not pairs:
        raise ValueError(tr("Не указан ни один банк и ключ для записи", "No target bank & key provided"))

    updates: list[tuple[SlotSpec, bytes]] = []
    for b_tok, k_tok in pairs:
        spec = parse_slot_selector(b_tok, allow_master=force_master)
        key_bytes = parse_hex_key(k_tok)
        for sev, msg in check_key_warnings(key_bytes):
            if sev == "STOP" and not allow_suspicious:
                raise ValueError(
                    f"{msg}\n"
                    + tr(
                        "(Для принудительной записи добавьте --allow-suspicious-key)",
                        "(Pass --allow-suspicious-key to override)",
                    )
                )
            print(f"⚠ {msg}", file=sys.stderr)
        updates.append((spec, key_bytes))
    return updates


def cmd_bind_cp(args: argparse.Namespace) -> int:
    cf_in = clean_user_path(args.cflash_in)
    df_in = clean_user_path(args.dflash_in)
    cf_out = clean_user_path(args.cflash_out)
    df_out = clean_user_path(args.dflash_out)
    updates = _collect_bank_key_updates(
        args.bank,
        args.key,
        args.set_pairs,
        force_master=args.force_master,
        allow_suspicious=args.allow_suspicious_key,
    )
    disp = _make_cli_display(args)
    patched_cf, patched_df, summary = bind_cp_turnkey(
        cf_in.read_bytes(),
        df_in.read_bytes(),
        updates,
        force_bypass_eeprom_mask=args.bypass_eeprom_mask,
        ignore_input_crc=args.ignore_input_crc,
        reporter=disp.create_reporter(),
    )
    disp.finish()
    cf_out.parent.mkdir(parents=True, exist_ok=True)
    df_out.parent.mkdir(parents=True, exist_ok=True)
    cf_out.write_bytes(patched_cf)
    df_out.write_bytes(patched_df)
    print(f"✓ CodeFlash -> {cf_out} (CRC-16: 0x{summary['cflash_crc16']:04X})")
    print(f"✓ DataFlash -> {df_out}")
    return 0


def cmd_patch_cflash(args: argparse.Namespace) -> int:
    in_path = clean_user_path(args.input)
    out_path = clean_user_path(args.output)
    mode = "restore_stock" if args.restore_stock else ("global_plain" if args.global_plain else "hybrid")
    disp = _make_cli_display(args)
    out_bytes, desc, new_crc = apply_cflash_patch(
        in_path.read_bytes(),
        mode=mode,
        bypass_eeprom_mask=args.bypass_eeprom_mask,
        cave_vaddr=args.cave_vaddr,
        ignore_input_crc=args.ignore_input_crc,
        reporter=disp.create_reporter(),
    )
    disp.finish()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out_bytes)
    print(f"✓ {desc}\n✓ {out_path} (CRC-16: 0x{new_crc:04X})")
    return 0


def cmd_set_cp_key(args: argparse.Namespace) -> int:
    in_path = clean_user_path(args.input)
    out_path = clean_user_path(args.output)
    updates = _collect_bank_key_updates(
        args.bank,
        args.key,
        args.set_pairs,
        force_master=args.force_master,
        allow_suspicious=args.allow_suspicious_key,
    )
    disp = _make_cli_display(args)
    out_df, _ = write_dflash_slots(in_path.read_bytes(), updates, reporter=disp.create_reporter())
    disp.finish()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out_df)
    print(f"✓ DataFlash -> {out_path}")
    return 0


def cmd_clear_cp_key(args: argparse.Namespace) -> int:
    in_path = clean_user_path(args.input)
    out_path = clean_user_path(args.output)
    specs = parse_slot_list(" ".join(args.banks), allow_master=args.force_master)
    disp = _make_cli_display(args)
    out_df = clear_dflash_slots(in_path.read_bytes(), specs, reporter=disp.create_reporter())
    disp.finish()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out_df)
    print(f"✓ DataFlash -> {out_path}")
    return 0


def cmd_patch_engineering(args: argparse.Namespace) -> int:
    if not args.cflash_in and not args.uflash_in:
        raise ValueError(tr("Укажите --cflash-in и/или --uflash-in", "Specify --cflash-in and/or --uflash-in"))
    if args.cflash_in and not args.cflash_out:
        raise ValueError(tr("Для --cflash-in обязательно укажите --cflash-out", "--cflash-out is required with --cflash-in"))
    if args.uflash_in and not args.uflash_out:
        raise ValueError(tr("Для --uflash-in обязательно укажите --uflash-out", "--uflash-out is required with --uflash-in"))

    disp = _make_cli_display(args)
    rep = disp.create_reporter()
    if args.cflash_in:
        cf_in = clean_user_path(args.cflash_in)
        cf_out = clean_user_path(args.cflash_out)
        patched_cf, desc, new_crc = apply_engineering_patch(
            cf_in.read_bytes(),
            restore_stock=args.restore_stock,
            ignore_input_crc=args.ignore_input_crc,
            reporter=rep,
        )
        cf_out.parent.mkdir(parents=True, exist_ok=True)
        cf_out.write_bytes(patched_cf)
        print(f"✓ CodeFlash: {desc} -> {cf_out} (CRC-16: 0x{new_crc:04X})")
    if args.uflash_in:
        uf_in = clean_user_path(args.uflash_in)
        uf_out = clean_user_path(args.uflash_out)
        patched_uf, udesc = apply_uflash_rsa_patch(
            uf_in.read_bytes(),
            restore_stock=args.restore_stock,
            reporter=rep,
        )
        uf_out.parent.mkdir(parents=True, exist_ok=True)
        uf_out.write_bytes(patched_uf)
        print(f"✓ Uflash: {udesc} -> {uf_out}")
    disp.finish()
    return 0


def _only_with(option: str, used: list[str]) -> None:
    """Options that change something only together with `option`: refuse them alone rather than ignore them."""
    if used:
        names = ", ".join(used)
        raise ValueError(tr(f"Без {option} эти параметры ничего не меняют: {names}",
                            f"Without {option} these options do nothing: {names}"))


def cmd_activate_swap(args: argparse.Namespace) -> int:
    if not args.auto_parameterize:
        _only_with("--auto-parameterize", [o for o, v in (
            ("--fpa-preset", args.fpa_preset), ("--button-mode", args.button_mode), ("--mfl-key", args.mfl_key),
            ("--kl15-memory", args.kl15_memory or None)) if v is not None])
    raw_df = clean_user_path(args.input).read_bytes()
    enable_tokens: list[str | int] = []
    if args.all_gateway:
        enable_tokens.extend(GATEWAY_SWAP_SLOT_ORDER)
    if args.all_supported:
        ds = analyze_dflash_datasets(raw_df)
        enable_tokens.extend(ds.supported_fecs)
    if args.enable_fecs:
        enable_tokens.extend(args.enable_fecs)
    disable_tokens: list[str | int] = list(args.disable_fecs or [])

    if not enable_tokens and not disable_tokens and not args.replace:
        if args.all_supported:
            raise ValueError(
                tr(
                    "В текущем DataFlash нет валидных датасетов ZDC — список поддерживаемых FeC пуст (укажите --fec явно)",
                    "No valid ZDC datasets found in current DataFlash — supported FeC list is empty (pass --fec explicitly)",
                )
            )
        raise ValueError(
            tr(
                "Укажите --fec / --all-supported / --all-gateway и/или --disable / --replace",
                "Specify --fec / --all-supported / --all-gateway and/or --disable / --replace",
            )
        )

    vin_arg: str | None = "" if args.no_vin else args.vin
    disp = _make_cli_display(args)
    rep = disp.create_reporter()

    if getattr(args, "auto_parameterize", False):
        cur_sw = analyze_dflash_swap(raw_df)
        target_set = set() if args.replace else {f.fec_code for f in cur_sw.active_fscs}
        target_set |= set(parse_fec_list(enable_tokens))  # same parsing as the activation itself: "a,b" works
        target_set -= set(parse_fec_list(disable_tokens))
        ap_cfg = ZdcAutoParamConfig(
            enabled=True,
            fpa_preset=args.fpa_preset or "surgical",
            button_mode=args.button_mode or "keep",
            mfl_keycode=0x19 if args.mfl_key is None else args.mfl_key,
            kl15_persist_profiles=args.kl15_memory,  # S029 only; the S075 pass-through has its own flag
        )
        raw_df, _ = parameterize_dflash_for_fecs(raw_df, sorted(target_set), ap_cfg, reporter=rep)

    out_df, summary = apply_dflash_swap_fecs(
        raw_df,
        enable_fecs=enable_tokens,
        disable_fecs=disable_tokens,
        vin=vin_arg,
        timestamp_unix=_u32_timestamp(args.timestamp),
        preserve_existing_active=not args.replace,
        reporter=rep,
    )
    disp.finish()

    out_p = clean_user_path(args.output)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_bytes(out_df)
    active_hex = ", ".join(summary["active_fecs"]) or "none"
    print(f"✓ DataFlash Multi-FSC -> {out_p} (NvM 0x7C CRC-32: 0x{summary['nvm_7c_crc32']:08X})")
    print(tr(f"  Активные FeC ({len(summary['active_fecs'])}): {active_hex}", f"  Active FeCs ({len(summary['active_fecs'])}): {active_hex}"))
    return 0


def cmd_parameterize(args: argparse.Namespace) -> int:
    if not args.button_mode:
        _only_with("--button-mode", [o for o, v in (
            ("--mfl-key", args.mfl_key), ("--mfl-long-press", args.mfl_long_press or None),
            ("--console-ring", args.console_ring), ("--mfl-ring", args.mfl_ring)) if v is not None])
    for opt, kmh in (("--mke-speed-on", args.mke_speed_on), ("--mke-speed-off-high", args.mke_speed_off_high)):
        if kmh is not None and not 0 <= kmh <= 255:
            raise ValueError(tr(f"{opt}: допустимо 0..255 км/ч, указано {kmh}", f"{opt}: allowed 0..255 km/h, given {kmh}"))
    raw_df = clean_user_path(args.input).read_bytes()
    disp = _make_cli_display(args)
    rep = disp.create_reporter()

    for spec in args.export_block or []:
        if "=" not in spec:
            raise ValueError(f"Expected IDX=PATH for --export-block, got '{spec}'")
        idx_s, p_s = spec.split("=", 1)
        idx = int(idx_s, 0)
        dest = clean_user_path(p_s)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(export_zdc_block(raw_df, idx))
        print(tr(f"✓ ZDC #{idx} экспортирован -> {dest}", f"✓ Exported ZDC #{idx} -> {dest}"))

    modified = False
    out_df = raw_df

    for spec in args.import_block or []:
        if "=" not in spec:
            raise ValueError(f"Expected IDX=PATH for --import-block, got '{spec}'")
        idx_s, p_s = spec.split("=", 1)
        idx = int(idx_s, 0)
        blob = clean_user_path(p_s).read_bytes()
        out_df = import_zdc_block(out_df, idx, blob, fix_crc=True, reporter=rep)
        modified = True

    if args.mke_preset:
        if args.mke_preset == "erase":
            out_df = erase_zdc_block(out_df, 1, reporter=rep)
        else:
            out_df = inject_mke_preset(out_df, args.mke_preset, reporter=rep)
        modified = True

    if args.mke_speed_on is not None or args.mke_speed_off_high is not None:
        mke = parse_mke_block(out_df)
        if mke.empty or not mke.plausible:
            out_df = inject_mke_preset(out_df, "86", reporter=rep)
            mke = parse_mke_block(out_df)
        if args.mke_speed_on is not None:
            mke.speed_on_kmh = args.mke_speed_on
        if args.mke_speed_off_high is not None:
            mke.speed_off_high_kmh = args.mke_speed_off_high
        out_df = apply_mke_config(out_df, mke, reporter=rep)
        modified = True

    if args.ssa_preset:
        if args.ssa_preset == "erase":
            out_df = erase_zdc_block(out_df, 2, reporter=rep)
        else:
            out_df = inject_ssa_preset(out_df, reporter=rep)
        modified = True

    if args.ssa_bap_mode is not None:
        ssa = parse_ssa_block(out_df)
        if ssa.empty or not ssa.crc_ok:
            out_df = inject_ssa_preset(out_df, reporter=rep)
            ssa = parse_ssa_block(out_df)
        ssa.bap_output_mode = args.ssa_bap_mode
        out_df = apply_ssa_config(out_df, ssa, reporter=rep)
        modified = True

    if args.bem_preset:
        if args.bem_preset == "erase":
            out_df = erase_zdc_block(out_df, 6, reporter=rep)
        else:
            out_df = inject_bem_preset(out_df, args.bem_preset, reporter=rep)
        modified = True

    for bspec in args.bem_slot or []:
        if "=" not in bspec:
            raise ValueError(f"Expected SLOT=ROM_IDX for --bem-slot, got '{bspec}'")
        s_tok, r_tok = bspec.split("=", 1)
        s_idx = int(s_tok, 0)
        r_idx = None if r_tok.strip().lower() in ("clear", "empty", "none", "ff") else int(r_tok, 0)
        out_df = replace_bem_slot_from_rom(out_df, s_idx, r_idx, reporter=rep)
        modified = True

    fpa_touched = any(
        (
            args.fpa_preset,
            args.enable_fpa_slots,
            args.disable_fpa_slots,
            args.button_mode,
            args.kl15_profiles,
            args.kl15_powertrain,
        )
    )
    if fpa_touched:
        cur_fpa = FpaDataset.from_dflash(out_df)
        loaded_fpa = FpaDataset(bytes(cur_fpa.buf))
        if args.fpa_preset == "erase":
            out_df = erase_zdc_block(out_df, 4, reporter=rep)
            cur_fpa = FpaDataset.from_dflash(out_df)
        else:
            if args.fpa_preset:
                fpa = build_fpa_preset_block(args.fpa_preset, target_schema=args.fpa_schema, existing_zdc4=bytes(cur_fpa.buf))
            elif cur_fpa.empty or not cur_fpa.crc_ok:
                fpa = build_fpa_preset_block("fwd_dcc", target_schema=args.fpa_schema)
            else:
                fpa = cur_fpa
            for sl in args.enable_fpa_slots or []:
                fpa.set_slot_enabled(int(sl), True)
            for sl in args.disable_fpa_slots or []:
                fpa.set_slot_enabled(int(sl), False)
            if args.button_mode:
                c_ring = [int(x, 0) for x in args.console_ring.split(",") if x.strip()] if args.console_ring else None
                m_ring = [int(x, 0) for x in args.mfl_ring.split(",") if x.strip()] if args.mfl_ring else None
                fpa.configure_buttons(
                    mode=args.button_mode,
                    mfl_keycode=0x19 if args.mfl_key is None else args.mfl_key,
                    mfl_long_press=args.mfl_long_press,
                    console_ring=c_ring,
                    mfl_ring=m_ring,
                )
            if args.kl15_profiles or args.kl15_powertrain:
                fpa.set_kl15_persistence(
                    persist_profiles=(args.kl15_profiles == "keep") if args.kl15_profiles else None,
                    persist_powertrain=(args.kl15_powertrain == "keep") if args.kl15_powertrain else None,
                    original=loaded_fpa,  # "reset" puts back what the dump had
                )
            out_df = apply_fpa_dataset(out_df, fpa, reporter=rep)
        modified = True

    if args.dataset_pn or args.dataset_ver or args.dataset_equip is not None:
        out_df = apply_zdc_passport(
            out_df,
            dataset_pn=args.dataset_pn,
            dataset_ver=args.dataset_ver,
            equip=args.dataset_equip,
            clean_pads=True,
            reporter=rep,
        )
        modified = True
    elif modified:
        pp = parse_zdc_passport(out_df)
        if pp.empty or not pp.crc_ok:
            ds_chk = analyze_dflash_datasets(out_df)
            if ds_chk.has_any_valid_dataset:
                out_df = apply_zdc_passport(out_df, reporter=rep)

    disp.finish()

    if modified:
        if not args.output:
            raise ValueError(tr("Укажите выходной файл -o / --output", "Provide -o / --output for modified DataFlash"))
        out_p = clean_user_path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(out_df)
        print(tr(f"✓ DataFlash параметрирован -> {out_p}", f"✓ Parameterized DataFlash -> {out_p}"))
    elif not args.export_block:
        raise ValueError(
            tr(
                "Не указано ни одной операции параметризации или экспорта (см. contitool parameterize --help)",
                "No parameterization or export options specified (see contitool parameterize --help)",
            )
        )
    return 0


def cmd_gen_rsa_key(args: argparse.Namespace) -> int:
    out_json = clean_user_path(args.output)
    disp = _make_cli_display(args)
    kp = generate_rsa1024_e3_keypair(reporter=disp.create_reporter())
    disp.finish()
    j_path, priv_path, pub_path = save_rsa1024_keypair_bundle(out_json, kp)
    print(f"✓ JSON        : {j_path}")
    print(f"✓ Private PEM : {priv_path}")
    print(f"✓ Public PEM  : {pub_path}")
    return 0


def cmd_set_rsa_key(args: argparse.Namespace) -> int:
    if not args.cflash_in and not args.dflash_in:
        raise ValueError(tr("Укажите --cflash-in и/или --dflash-in", "Provide --cflash-in and/or --dflash-in"))
    if args.cflash_in and not args.cflash_out:
        raise ValueError(tr("Укажите --cflash-out", "Provide --cflash-out"))
    if args.dflash_in and not args.dflash_out:
        raise ValueError(tr("Укажите --dflash-out", "Provide --dflash-out"))
    if args.dflash_in and args.target == "fbl":
        raise ValueError(tr(
            "--dflash-in: в DataFlash хранится только ключ SWaP, с --target fbl менять там нечего. "
            "Уберите --dflash-in или укажите --target swap / both",
            "--dflash-in: DataFlash holds only the SWaP key, with --target fbl there is nothing to change there. "
            "Leave out --dflash-in or use --target swap / both",
        ))

    disp = _make_cli_display(args)
    rep = disp.create_reporter()
    patch_swap = args.target in ("swap", "both")
    patch_fbl = args.target in ("fbl", "both")

    if args.restore_stock:
        swap_mod = STOCK_SWAP_MODULUS
        fbl_mod = STOCK_FBL_MODULUS
    elif args.generate_key:
        kp = generate_rsa1024_e3_keypair(reporter=rep)
        j_path, priv_path, _ = save_rsa1024_keypair_bundle(clean_user_path(args.generate_key), kp)
        print(f"✓ Generated RSA-1024 keypair: {j_path} ({priv_path})")
        swap_mod = bytes.fromhex(kp["n_hex"])
        fbl_mod = swap_mod
    elif args.key:
        mod, _ = load_rsa1024_key_material(args.key)
        swap_mod = mod
        fbl_mod = mod
    else:
        raise ValueError(
            tr(
                "Укажите --key, --generate-key или --restore-stock",
                "Specify --key, --generate-key, or --restore-stock",
            )
        )

    if args.cflash_in:
        raw_cf = clean_user_path(args.cflash_in).read_bytes()
        if args.restore_stock and patch_swap and patch_fbl:
            raw_cf, _, _ = apply_cflash_rsa_modulus(
                raw_cf, swap_mod, patch_swap=True, patch_fbl=False, ignore_input_crc=args.ignore_input_crc, reporter=rep
            )
            out_cf, _, new_crc = apply_cflash_rsa_modulus(
                raw_cf, fbl_mod, patch_swap=False, patch_fbl=True, ignore_input_crc=True, reporter=rep
            )
        else:
            mod_use = swap_mod if patch_swap else fbl_mod
            out_cf, _, new_crc = apply_cflash_rsa_modulus(
                raw_cf,
                mod_use,
                patch_swap=patch_swap,
                patch_fbl=patch_fbl,
                ignore_input_crc=args.ignore_input_crc,
                reporter=rep,
            )
        cf_out = clean_user_path(args.cflash_out)
        cf_out.parent.mkdir(parents=True, exist_ok=True)
        cf_out.write_bytes(out_cf)
        print(f"✓ CodeFlash -> {cf_out} (CRC-16: 0x{new_crc:04X})")

    if args.dflash_in:
        raw_df = clean_user_path(args.dflash_in).read_bytes()
        out_df, crc32_val, _ = apply_dflash_swap_rsa_modulus(raw_df, swap_mod, reporter=rep)
        df_out = clean_user_path(args.dflash_out)
        df_out.parent.mkdir(parents=True, exist_ok=True)
        df_out.write_bytes(out_df)
        print(f"✓ DataFlash -> {df_out} (NvM 0x7C CRC-32: 0x{crc32_val:08X})")

    disp.finish()
    return 0


def cmd_sign_fsc(args: argparse.Namespace) -> int:
    n_bytes, d_int = load_rsa1024_key_material(args.key)
    if d_int is None:
        raise ValueError(
            tr(
                "Для подписи нужен приватный ключ RSA-1024 (.json или .private.pem с экспонентой d)!",
                "Signing requires a private RSA-1024 key (.json or .private.pem containing private exponent d)!",
            )
        )
    fec_code = parse_fec_code(args.fec)
    vcrn_5b = b""
    vin_str = ""
    if args.dflash:
        sw = analyze_dflash_swap(clean_user_path(args.dflash).read_bytes())
        vcrn_5b = sw.vcrn
        vin_str = sw.vin
    if args.vcrn:
        vcrn_clean = args.vcrn.strip().replace(" ", "").replace(":", "")
        vcrn_5b = bytes.fromhex(vcrn_clean)
    if args.no_vin:
        vin_str = ""
    elif args.vin is not None:
        vin_str = args.vin

    if len(vcrn_5b) != 5:
        raise ValueError(
            tr(
                "Укажите 5-байтный --vcrn (10 hex-символов) или передайте --dflash для авточтения VCRN!",
                "Provide 5-byte --vcrn (10 hex chars) or pass --dflash to auto-extract VCRN!",
            )
        )

    disp = _make_cli_display(args)
    fsc = build_signed_fsc(
        fec_code,
        vcrn_5b,
        vin_str,
        n_bytes,
        d_int,
        timestamp_unix=_u32_timestamp(args.timestamp),
        reporter=disp.create_reporter(),
    )
    disp.finish()
    if args.output:
        out_p = clean_user_path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(fsc)
        print(f"✓ FSC (171 B) -> {out_p}")
    print(f"FSC HEX (0xAB): {fsc.hex().upper()}")
    print(f"UDS Routine 0x0655: 3101065500{fsc.hex().upper()}")
    return 0


def cmd_sign_odx(args: argparse.Namespace) -> int:
    n_bytes, d_int = load_rsa1024_key_material(args.key)
    if d_int is None:
        raise ValueError(
            tr(
                "Для подписи ODX нужен приватный ключ RSA-1024 (.json или .private.pem)!",
                "ODX signing requires a private RSA-1024 key (.json or .private.pem)!",
            )
        )
    disp = _make_cli_display(args)
    sig = sign_fbl_odx_application(
        clean_user_path(args.input).read_bytes(),
        n_bytes,
        d_int,
        ignore_input_crc=args.ignore_input_crc,
        reporter=disp.create_reporter(),
    )
    disp.finish()
    if args.output:
        out_p = clean_user_path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(sig)
        print(f"✓ Signature (128 B) -> {out_p}")
    print(f"<FW-SIGNATURE TYPE=\"A_BYTEFIELD\">{sig.hex().upper()}</FW-SIGNATURE>")
    return 0


def print_dtc_report(records: list[dict]) -> None:
    """Faults first (active, then stored) with ODIS code and description; codes never tested are only counted."""
    groups: dict[str, list[tuple[int, int]]] = {"active": [], "stored": [], "untested": []}
    for r in records:
        code, st = int(str(r.get("dtc", "0")), 16), int(str(r.get("status", "0")), 16)
        groups[dtc.group(st)].append((code, st))
    titles = {
        "active": tr("Активные — неисправность есть сейчас", "Active — failing now"),
        "stored": tr("Сохранённые — неисправность была", "Stored — failed earlier"),
    }
    for key in ("active", "stored"):
        if not groups[key]:
            continue
        print(f"\n{titles[key]} ({len(groups[key])}):")
        for code, st in groups[key]:
            display, text = dtc.describe(code)
            print(f"  {display or '-':<8} {code:06X}  {text}  [{dtc.status_text(st)}]")
    if not groups["active"] and not groups["stored"]:
        print(tr("Неисправностей нет.", "No faults."))
    if groups["untested"]:
        print(
            tr(
                f"Ещё {len(groups['untested'])} проверок блок не выполнял после стирания ошибок — результата у них нет, "
                "это не неисправности.",
                f"{len(groups['untested'])} more checks have not run since codes were cleared — they have no result, "
                "these are not faults.",
            )
        )


def cmd_can(args: argparse.Namespace) -> int:
    action = args.can_action
    if action == "ports":
        from contitool.can import dpdu

        ports = discover_serial_ports()
        passthru = discover_j2534()
        pdu_apis = dpdu.discover_dpdu()
        if not ports and not passthru and not pdu_apis:
            print(tr("Адаптеры не обнаружены (USB/COM порты и J2534).", "No adapters detected (USB/COM ports and J2534)."))
            return 0
        for p in ports:
            tag = "★ CAN" if p.is_likely_can else "  USB"
            print(f"{tag}  {p.device:<36}  {p.description}")
        for d in passthru:
            note = "" if d.usable else tr(f"  [драйвер {d.bits}-бит — не подходит]", f"  [{d.bits}-bit driver — not usable]")
            print(f"J2534  {d.name:<36}  {d.dll}{note}")
        if passthru:
            print(tr('J2534: --interface j2534 --port "<имя>"', 'J2534: --interface j2534 --port "<name>"'))
        for api in pdu_apis:
            note = "" if dpdu.driver_supported(api["version"]) else tr(
                "  [версия не проверена — нужен --allow-dpdu-driver]", "  [unverified version — needs --allow-dpdu-driver]")
            print(f"D-PDU  {api['name']:<36}  {api['version'] or '?'}{note}")
        return 0

    if not args.port and args.interface not in ("j2534", "dpdu"):  # these pick the installed driver themselves
        raise ValueError(
            tr(
                "Укажите порт адаптера через --port (список портов: contitool can ports)",
                "Specify adapter port via --port (list available ports with: contitool can ports)",
            )
        )

    if args.interface == "dpdu" and args.allow_dpdu_driver:
        from contitool.can import dpdu

        dpdu.accepted_drivers.update(api["version"] for api in dpdu.discover_dpdu())

    write_actions = ("write-uflash", "write-dflash", "write-cflash", "turnkey", "zdc-upload")
    if action in write_actions and not args.yes:
        raise ValueError(
            tr(
                f"Операция '{action}' стирает и перепрошивает память шлюза. Убедитесь, что включён CAN-терминатор (или стоит резистор 120 Ом) "
                "и стабильного питания +12 В, затем добавьте флаг --yes.",
                f"Operation '{action}' erases and programs gateway flash. Confirm CAN termination is on (or a 120 Ohm resistor is fitted) "
                "and stable +12V bench power, then pass --yes.",
            )
        )

    base_out = clean_user_path(args.output_dir) if args.output_dir else None
    session_dir = default_session_dir(base_out, action.replace("-", "_"))
    disp = _make_cli_display(args)
    rep = disp.create_reporter()

    try:
        if action == "verify":
            res = can_verify(args.port, interface=args.interface, session_dir=session_dir, reporter=rep)
            print(f"✓ RSA status: {res['rsa_status']} | Session: {res['session_dir']}")
        elif action == "backup":
            ident = can_identify(args.port, interface=args.interface)
            print(tr("Блок на связи:", "ECU found:"))
            for item in ident["ident"]:
                print(f"  {tr(item['label_ru'], item['label_en']):<22} {item['value']}")
            if not args.yes and sys.stdin.isatty():
                answer = input(tr("Продолжить чтение памяти? [y/N] ", "Read the ECU memory? [y/N] ")).strip().lower()
                if answer not in ("y", "yes", "д", "да"):
                    print(tr("Отменено.", "Cancelled."))
                    return 1
            res = can_backup(args.port, interface=args.interface, session_dir=session_dir, reporter=rep)
            print(f"✓ Backup folder: {res['session_dir']}")
        elif action == "read-mem":
            if args.address is None or args.length is None:
                raise ValueError(
                    tr(
                        "Для read-mem укажите --address 0x... и --length ЧИСЛО_БАЙТ",
                        "read-mem requires --address 0x... and --length BYTE_COUNT",
                    )
                )
            out_bin = (
                clean_user_path(args.out_file)
                if args.out_file
                else (session_dir / f"mem_0x{args.address:08X}_{args.length}.bin")
            )
            res = can_read_memory(
                args.port,
                args.address,
                args.length,
                out_bin,
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(tr(f"✓ Дамп памяти ({res['bytes']:,} Б) -> {out_bin} | Сессия: {res['session_dir']}",
                     f"✓ Memory dump ({res['bytes']:,} B) -> {out_bin} | Session: {res['session_dir']}"))
        elif action == "health":
            res = can_health_check(
                args.port,
                interface=args.interface,
                session_dir=session_dir,
                clear_dtc=args.clear_dtc,
                reporter=rep,
            )
            print(tr(f"✓ Шлюз на связи | Сессия: {res['session_dir']}", f"✓ Gateway online | Session: {res['session_dir']}"))
            print_dtc_report(res.get("dtc_records") or [])
        elif action == "write-uflash":
            in_uf = clean_user_path(args.input) if args.input else None
            res = can_write_uflash(
                args.port,
                input_uflash=in_uf,
                restore_stock=args.restore_stock,
                raw_image=args.raw_image,
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(f"✓ Uflash programmed & verified | Session: {res['session_dir']}")
        elif action == "write-dflash":
            if not args.input:
                raise ValueError(
                    tr(
                        "Для write-dflash укажите -i / --input ПУТЬ_К_DFLASH.bin",
                        "write-dflash requires -i / --input PATH_TO_DFLASH.bin",
                    )
                )
            res = can_write_dflash(
                args.port,
                clean_user_path(args.input),
                full_rewrite=args.full_rewrite,
                allow_icus_tail=args.allow_icus_tail,
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(
                f"✓ DataFlash programmed & verified ({res.get('blocks_changed', 0)} blocks) | Session: {res['session_dir']}"
            )
        elif action == "write-cflash":
            if not args.input:
                raise ValueError(tr("Для write-cflash укажите -i / --input ПУТЬ_К_CFLASH.bin", "write-cflash requires -i / --input PATH_TO_CFLASH.bin"))
            res = can_write_cflash(
                args.port,
                clean_user_path(args.input),
                ignore_input_crc=args.ignore_input_crc,
                raw_faci=args.raw_faci,
                preserve_selfid=not args.overwrite_selfid,
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(f"✓ CodeFlash programmed & verified | Session: {res['session_dir']}")
        elif action == "turnkey":
            cp_updates = None
            if args.set_pairs:
                cp_updates = _collect_bank_key_updates(
                    None,
                    None,
                    args.set_pairs,
                    force_master=args.force_master,
                    allow_suspicious=args.allow_suspicious_key,
                )
            res = can_turnkey_read_patch_flash(
                args.port,
                patch_cp_hybrid=not args.no_cp_patch,
                bypass_eeprom_mask=args.bypass_eeprom_mask,
                patch_engineering_cflash=not args.no_engineering_patch,
                unlock_engineering_uflash=True,
                cp_updates=cp_updates,
                clear_dtc_after=args.clear_dtc,
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(f"✓ Turnkey CAN workflow complete | Session: {res['session_dir']}")
        elif action == "zdc-upload":
            if not args.input:
                raise ValueError(
                    tr(
                        "Для zdc-upload укажите -i / --input ПУТЬ_К_DFLASH.bin",
                        "zdc-upload requires -i / --input PATH_TO_DFLASH.bin",
                    )
                )
            res = can_upload_zdc_datasets(
                args.port,
                clean_user_path(args.input).read_bytes(),
                interface=args.interface,
                session_dir=session_dir,
                reporter=rep,
            )
            print(tr(f"✓ Загружено блоков ZDC: {len(res['uploaded_blocks'])} | Сессия: {res.get('session_dir', session_dir)}",
                     f"✓ ZDC blocks uploaded ({len(res['uploaded_blocks'])}) | Session: {res.get('session_dir', session_dir)}"))
        elif action == "learn-mfl":
            res = can_learn_mfl_button(args.port, interface=args.interface, reporter=rep)
            if res.get("captured") and res.get("keycode"):
                print(f"✓ MFL_Tastencode = 0x{int(res['keycode']):02X} ({tr(res.get('label_ru', ''), res.get('label_en', ''))})")
            elif res.get("gra_button_detected"):
                print(tr("⚠ Нажата кнопка круиз-контроля GRA_Neu / Travel Assist (нет MFL_Tastencode)",
                         "⚠ GRA_Neu cruise/Travel Assist key detected (no MFL_Tastencode)"))
            else:
                print(tr("⚠ За время ожидания нажатие кнопки руля не обнаружено", "⚠ No MFL button press detected within timeout"))
    finally:
        disp.finish()
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="contitool",
        description=tr(
            f"ContiTool v{__version__} — Графическая студия и CLI для шлюзов Continental VAG MQB J533 (RH850/F1L)",
            f"ContiTool v{__version__} — Desktop GUI Studio & CLI for Continental VAG MQB Gateway J533 (RH850/F1L)",
        ),
    )
    ap.add_argument("--version", action="version", version=f"ContiTool v{__version__}")
    ap.add_argument("-l", "--lang", type=_cli_lang_type, choices=("ru", "en"), help=tr("Язык: ru / en", "Language: ru / en"))
    ap.add_argument("--no-color", action="store_true", help=tr("Отключить ANSI-цвета", "Disable ANSI colors"))

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("-l", "--lang", type=_cli_lang_type, choices=("ru", "en"), default=argparse.SUPPRESS)
    sub_common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)

    sub = ap.add_subparsers(dest="cmd", required=False)

    def _add(name: str, desc: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[sub_common], help=desc, description=desc)

    p_gui = _add("gui", tr("Запустить графическую программу ContiTool (по умолчанию без аргументов)", "Launch ContiTool Desktop GUI (default when run without arguments)"))
    p_gui.set_defaults(func=cmd_gui)

    p_wiz = _add("wizard", tr("Псевдоним для запуска графического интерфейса ContiTool", "Alias to launch ContiTool Desktop GUI"))
    p_wiz.set_defaults(func=cmd_gui)

    p_bnk = _add("banks", tr("Показать справочник всех 12 банков CP и адресов DataFlash", "Show reference table of all 12 CP banks & DataFlash offsets"))
    p_bnk.set_defaults(func=cmd_banks)

    p_gde = _add("guide", tr("Показать краткую памятку (программатор 64 КБ, распиновка T20, ключи IKA)", "Show bench reference guide (64 KB programmer rule, T20 pinout, IKA keys)"))
    p_gde.set_defaults(func=cmd_guide)

    p_ins = _add("inspect", tr("Проверить дампы CodeFlash, DataFlash (12 банков CP + SWaP) и/или Uflash", "Inspect CodeFlash, DataFlash (12 CP banks + SWaP), and/or Uflash dumps"))
    p_ins.add_argument("--cflash", help=tr("Путь к CodeFlash.bin (1.5 МБ) или FD_0DATA", "Path to CodeFlash.bin (1.5 MB) or FD_0DATA"))
    p_ins.add_argument("--dflash", help=tr("Путь к DataFlash.bin (64 КБ)", "Path to DataFlash.bin (64 KB)"))
    p_ins.add_argument("--uflash", help=tr("Путь к Uflash.bin (32 КБ)", "Path to Uflash.bin (32 KB)"))
    p_ins.set_defaults(func=cmd_inspect)

    p_bcp = _add("bind-cp", tr("Под ключ: пропатчить CodeFlash + записать 16Б ключи IKA в DataFlash", "Turnkey: patch CodeFlash + write 16B IKA keys into DataFlash"))
    p_bcp.add_argument("--cflash-in", required=True)
    p_bcp.add_argument("--dflash-in", required=True)
    p_bcp.add_argument("--cflash-out", required=True)
    p_bcp.add_argument("--dflash-out", required=True)
    p_bcp.add_argument("-b", "-s", "--bank", "--slot", dest="bank")
    p_bcp.add_argument("-k", "--key")
    p_bcp.add_argument("--set", dest="set_pairs", action="append", metavar="BANK=KEY")
    p_bcp.add_argument("--bypass-eeprom-mask", action="store_true")
    p_bcp.add_argument("--force-master", action="store_true")
    p_bcp.add_argument("--allow-suspicious-key", action="store_true")
    p_bcp.add_argument("--ignore-input-crc", action="store_true")
    p_bcp.set_defaults(func=cmd_bind_cp)

    p_pat = _add("patch-cflash", tr("Установить гибридный патч KSCHUTZ и пересчитать App CRC-16", "Install hybrid KSCHUTZ CP patch and recalculate App CRC-16"))
    p_pat.add_argument("-i", "--input", required=True)
    p_pat.add_argument("-o", "--output", required=True)
    mgrp = p_pat.add_mutually_exclusive_group()
    mgrp.add_argument("--global-plain", action="store_true")
    mgrp.add_argument("--restore-stock", action="store_true")
    p_pat.add_argument("--cave-vaddr", type=lambda x: int(x, 0), default=DEFAULT_CAVE_VADDR)
    p_pat.add_argument("--bypass-eeprom-mask", action="store_true")
    p_pat.add_argument("--ignore-input-crc", action="store_true")
    p_pat.set_defaults(func=cmd_patch_cflash)

    p_key = _add("set-cp-key", tr("Записать 16-байтный открытый ключ IKA в банк(и) 1..12 DataFlash.bin", "Write 16-byte plaintext IKA key into bank(s) 1..12 of DataFlash.bin"))
    p_key.add_argument("-i", "--input", required=True)
    p_key.add_argument("-o", "--output", required=True)
    p_key.add_argument("-b", "-s", "--bank", "--slot", dest="bank")
    p_key.add_argument("-k", "--key")
    p_key.add_argument("--set", dest="set_pairs", action="append", metavar="BANK=KEY")
    p_key.add_argument("--force-master", action="store_true")
    p_key.add_argument("--allow-suspicious-key", action="store_true")
    p_key.set_defaults(func=cmd_set_cp_key)

    p_clr = _add("clear-cp-key", tr("Очистить выбранные банки CP в DataFlash.bin (FF..FF)", "Clear selected CP banks in DataFlash.bin back to FF..FF"))
    p_clr.add_argument("-i", "--input", required=True)
    p_clr.add_argument("-o", "--output", required=True)
    p_clr.add_argument("-b", "-s", "--bank", "--slot", dest="banks", nargs="+", required=True)
    p_clr.add_argument("--force-master", action="store_true")
    p_clr.set_defaults(func=cmd_clear_cp_key)

    p_eng = _add("patch-engineering", tr("Инженерный режим (RSA-Free Uflash и/или Feature 0x80/81/83 + CCP в CodeFlash)", "Engineering Mode (RSA-Free Uflash and/or Feature 0x80/81/83 + CCP in CodeFlash)"))
    p_eng.add_argument("-i", "--cflash-in", dest="cflash_in")
    p_eng.add_argument("-o", "--cflash-out", dest="cflash_out")
    p_eng.add_argument("--uflash-in")
    p_eng.add_argument("--uflash-out")
    p_eng.add_argument("--restore-stock", action="store_true")
    p_eng.add_argument("--ignore-input-crc", action="store_true")
    p_eng.set_defaults(func=cmd_patch_engineering)

    p_asw = _add(
        "activate-swap",
        tr(
            "Прямая активация/деактивация функций SWaP FeC в DataFlash (Multi-FSC, без ключей RSA и без патча CodeFlash)",
            "Directly activate/deactivate SWaP FeC features in DataFlash (Multi-FSC, no RSA keys or CodeFlash edits)",
        ),
    )
    p_asw.add_argument("-i", "--input", required=True, help=tr("Путь к входному DataFlash.bin (64 КБ)", "Input DataFlash.bin path (64 KB)"))
    p_asw.add_argument("-o", "--output", required=True, help=tr("Путь к выходному DataFlash.bin", "Output DataFlash.bin path"))
    p_asw.add_argument(
        "-f",
        "--fec",
        "--enable",
        dest="enable_fecs",
        nargs="+",
        help=tr("Коды FeC для активации (напр. 10000100 10000300 10001100)", "FeC codes to enable (e.g. 10000100 10000300 10001100)"),
    )
    p_asw.add_argument(
        "--disable",
        dest="disable_fecs",
        nargs="+",
        help=tr("Коды FeC для отключения", "FeC codes to disable"),
    )
    p_asw.add_argument(
        "--all-supported",
        action="store_true",
        help=tr("Включить все функции FeC, поддерживаемые текущим датасетом ZDC", "Enable all FeCs supported by current ZDC dataset"),
    )
    p_asw.add_argument(
        "--all-gateway",
        action="store_true",
        help=tr("Включить все 13 стандартных функций шлюза J533", "Enable all 13 standard J533 Gateway FeCs"),
    )
    p_asw.add_argument(
        "--replace",
        action="store_true",
        help=tr("Отключить ранее активные FeC, не вошедшие в список включения", "Deactivate previously active FeCs not in the enabled set"),
    )
    p_asw.add_argument("--vin", help=tr("Переопределить 17-символьный VIN в слотах FSC", "Override 17-char VIN in FSC slots"))
    p_asw.add_argument("--no-vin", action="store_true", help=tr("Не привязывать слоты FSC к VIN (00..00)", "Leave VIN empty (00..00) in FSC slots"))
    p_asw.add_argument("--timestamp", type=lambda x: int(x, 0), default=None, help=tr("Unix-время для слотов FSC", "Unix timestamp for FSC slots"))
    p_asw.add_argument(
        "--auto-parameterize",
        action="store_true",
        help=tr("Автоматически параметрировать ZDC #1 / ZDC #4 под включаемые функции FeC", "Auto-parameterize ZDC #1 / ZDC #4 for enabled FeC features"),
    )
    p_asw.add_argument("--fpa-preset", choices=("surgical", "fwd", "fwd_dcc", "awd", "awd_dcc"))
    p_asw.add_argument("--button-mode", choices=("keep", "console", "both", "mfl"))
    p_asw.add_argument("--mfl-key", type=lambda x: int(x, 0))
    p_asw.add_argument("--kl15-memory", action="store_true", help=tr("Оставлять выбранный профиль после выключения зажигания", "Keep the selected profile after the ignition is off"))
    p_asw.set_defaults(func=cmd_activate_swap)

    p_par = _add(
        "parameterize",
        tr(
            "Редактирование параметрии ZDC в DataFlash (FPA профили, кнопки MODE+MFL, память Kl.15, MKE, Старт-Стоп, BEM, паспорт)",
            "Edit ZDC parameterization in DataFlash (FPA profiles, MODE+MFL buttons, Kl.15 memory, MKE, Start-Stop, BEM, passport)",
        ),
    )
    p_par.add_argument("-i", "--input", required=True, help=tr("Входной DataFlash.bin (64 КБ)", "Input DataFlash.bin (64 KB)"))
    p_par.add_argument("-o", "--output", help=tr("Выходной DataFlash.bin", "Output DataFlash.bin"))
    p_par.add_argument("--fpa-preset", choices=("fwd", "fwd_dcc", "awd", "awd_dcc", "erase"))
    p_par.add_argument("--fpa-schema", choices=("JC00", "PC00", "NC00"))
    p_par.add_argument("--enable-fpa-slots", type=int, nargs="+")
    p_par.add_argument("--disable-fpa-slots", type=int, nargs="+")
    p_par.add_argument("--button-mode", choices=("none", "console", "mfl", "both"))
    p_par.add_argument("--mfl-key", type=lambda x: int(x, 0))
    p_par.add_argument("--mfl-long-press", action="store_true")
    p_par.add_argument("--console-ring")
    p_par.add_argument("--mfl-ring")
    p_par.add_argument("--kl15-profiles", choices=("keep", "reset"))
    p_par.add_argument("--kl15-powertrain", choices=("keep", "reset"))
    p_par.add_argument("--mke-preset", choices=("86", "84", "erase"))
    p_par.add_argument("--mke-speed-on", type=int)
    p_par.add_argument("--mke-speed-off-high", type=int)
    p_par.add_argument("--ssa-preset", choices=("4C", "erase"))
    p_par.add_argument("--ssa-bap-mode", type=int, choices=(0, 1, 2, 3))
    p_par.add_argument("--bem-preset", choices=("2222", "0101", "erase"))
    p_par.add_argument("--bem-slot", action="append", metavar="SLOT=ROM_IDX")
    p_par.add_argument("--dataset-pn")
    p_par.add_argument("--dataset-ver")
    p_par.add_argument("--dataset-equip")
    p_par.add_argument("--export-block", action="append", metavar="IDX=PATH")
    p_par.add_argument("--import-block", action="append", metavar="IDX=PATH")
    p_par.set_defaults(func=cmd_parameterize)

    p_grk = _add("gen-rsa-key", tr("Сгенерировать ключевую пару RSA-1024 (e = 3) в .json + .pem", "Generate RSA-1024 (e = 3) keypair (.json + .pem)"))
    p_grk.add_argument("-o", "--output", required=True)
    p_grk.set_defaults(func=cmd_gen_rsa_key)

    p_srk = _add("set-rsa-key", tr("Вшить модуль RSA-1024 (e = 3) в CodeFlash и/или DataFlash NvM 0x7C", "Embed RSA-1024 (e = 3) public modulus into CodeFlash and/or DataFlash NvM 0x7C"))
    p_srk.add_argument("-k", "--key")
    p_srk.add_argument("--generate-key")
    p_srk.add_argument("--cflash-in")
    p_srk.add_argument("--cflash-out")
    p_srk.add_argument("--dflash-in")
    p_srk.add_argument("--dflash-out")
    p_srk.add_argument("--target", choices=("swap", "fbl", "both"), default="swap")
    p_srk.add_argument("--restore-stock", action="store_true")
    p_srk.add_argument("--ignore-input-crc", action="store_true")
    p_srk.set_defaults(func=cmd_set_rsa_key)

    p_fsc = _add("sign-fsc", tr("Подписать 171-байтный сертификат SWaP FSC v2 (RIPEMD-160 + RSA-1024)", "Sign 171-byte SWaP FSC v2 certificate (RIPEMD-160 + RSA-1024)"))
    p_fsc.add_argument("-k", "--key", required=True)
    p_fsc.add_argument("--fec", required=True)
    p_fsc.add_argument("--dflash")
    p_fsc.add_argument("--vcrn")
    p_fsc.add_argument("--vin")
    p_fsc.add_argument("--no-vin", action="store_true")
    p_fsc.add_argument("--timestamp", type=lambda x: int(x, 0), default=None)
    p_fsc.add_argument("-o", "--output")
    p_fsc.set_defaults(func=cmd_sign_fsc)

    p_odx = _add("sign-odx", tr("Подписать прошивку CodeFlash / FD_0DATA для ODX (<FW-SIGNATURE>)", "Sign CodeFlash / FD_0DATA for ODX (<FW-SIGNATURE>)"))
    p_odx.add_argument("-i", "--input", required=True)
    p_odx.add_argument("-k", "--key", required=True)
    p_odx.add_argument("-o", "--output")
    p_odx.add_argument("--ignore-input-crc", action="store_true")
    p_odx.set_defaults(func=cmd_sign_odx)

    iface_choices = tuple(code for code, _, _ in SUPPORTED_CAN_INTERFACES)
    p_can = _add("can", tr("Работа со шлюзом по Diagnosis CAN (500 кбит/с, нужен CAN-терминатор или резистор 120 Ом)", "Live Diagnosis CAN operations (500 kbit/s, CAN termination or a 120 Ohm resistor required)"))
    p_can.add_argument(
        "can_action",
        choices=("ports", "verify", "backup", "read-mem", "write-uflash", "write-dflash", "write-cflash", "zdc-upload", "learn-mfl", "health", "turnkey"),
    )
    p_can.add_argument("--port", help=tr("Порт адаптера (напр. COM4 или /dev/cu.usbmodem...)", "Adapter port (e.g. COM4 or /dev/cu.usbmodem...)"))
    p_can.add_argument("--interface", choices=iface_choices, default="slcan")
    p_can.add_argument(
        "-i",
        "--input",
        "--dflash",
        "--cflash",
        "--uflash",
        dest="input",
        help=tr("Входной дамп для write-uflash / write-dflash / write-cflash", "Input dump for write-uflash / write-dflash / write-cflash"),
    )
    p_can.add_argument("-o", "--output-dir", help=tr("Папка для сохранения бэкапов и отчётов (по умолчанию contitool_runs рядом с программой)", "Base output directory (default: contitool_runs next to the program)"))
    p_can.add_argument("--address", type=lambda x: int(x, 0), help=tr("Начальный адрес для read-mem (напр. 0xFF200000)", "Start address for read-mem (e.g. 0xFF200000)"))
    p_can.add_argument("--length", type=lambda x: int(x, 0), help=tr("Длина в байтах для read-mem (напр. 0x10000)", "Byte length for read-mem (e.g. 0x10000)"))
    p_can.add_argument("--out-file", help=tr("Путь к выходному файлу для read-mem", "Output file path for read-mem"))
    p_can.add_argument("--restore-stock", action="store_true", help=tr("Вернуть заводскую проверку RSA в write-uflash", "Restore stock RSA check in write-uflash"))
    p_can.add_argument("--raw-image", action="store_true", help=tr("Записать входной Uflash без автопатча", "Write raw Uflash image without auto-patching"))
    p_can.add_argument("--full-rewrite", action="store_true", help=tr("Перезаписать все пользовательские блоки DataFlash (для write-dflash)", "Rewrite all user DataFlash blocks (for write-dflash)"))
    p_can.add_argument("--allow-icus-tail", action="store_true", help=tr("Разрешить запись в область 0xF800..0xFFFF (только при явной необходимости)", "Allow writing DataFlash tail 0xF800..0xFFFF"))
    p_can.add_argument("--raw-faci", action="store_true", help=tr("Записать все изменённые блоки CodeFlash напрямую через FACI без UDS", "Write all changed CodeFlash blocks directly via FACI without UDS"))
    p_can.add_argument("--overwrite-selfid", action="store_true", help=tr("Не сохранять родной SELFID процессора при записи бут-сектора 0xAB00", "Allow overwriting MCU SELFID at 0x0000AB00"))
    p_can.add_argument("--ignore-input-crc", action="store_true")
    p_can.add_argument("--set", dest="set_pairs", action="append", metavar="BANK=KEY", help=tr("Прописать ключи IKA в DataFlash по CAN (для turnkey)", "Bind IKA keys into DataFlash over CAN (for turnkey)"))
    p_can.add_argument("--force-master", action="store_true")
    p_can.add_argument("--allow-suspicious-key", action="store_true")
    p_can.add_argument("--clear-dtc", action="store_true", help=tr("Очистить ошибки DTC (для health / turnkey)", "Clear DTCs (for health / turnkey)"))
    p_can.add_argument("--bypass-eeprom-mask", action="store_true", help=tr("Включить обход маски 95640 (для turnkey)", "Enable 95640 mask bypass (for turnkey)"))
    p_can.add_argument("--no-cp-patch", action="store_true", help=tr("Не патчить KSCHUTZ CP в turnkey", "Skip KSCHUTZ CP patch in turnkey"))
    p_can.add_argument("--no-engineering-patch", action="store_true", help=tr("Не патчить Engineering Mode в CodeFlash в turnkey", "Skip CodeFlash Engineering patch in turnkey"))
    p_can.add_argument("--yes", action="store_true", help=tr("Подтвердить запись во Flash и включённый CAN-терминатор", "Confirm flash erase/write and CAN termination"))
    p_can.add_argument(
        "--allow-dpdu-driver",
        action="store_true",
        help=tr("Разрешить установленный драйвер D-PDU непроверенной версии (он перепрошьёт VCI под себя)",
                "Allow an unverified installed D-PDU driver version (it reflashes the VCI to its own version)"),
    )
    p_can.set_defaults(func=cmd_can)

    return ap


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    early_lang = detect_early_cli_lang(raw_argv)
    if early_lang:
        set_lang(early_lang)

    ap = build_arg_parser()
    args = ap.parse_args(raw_argv)
    if getattr(args, "lang", None):
        set_lang(args.lang)

    if args.cmd is None or args.cmd in ("gui", "wizard"):
        return cmd_gui(args)

    for name in ("stdin", "stdout", "stderr"):  # None in a windowed build (no console): run the command all the same
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "r" if name == "stdin" else "w", encoding="utf-8"))
    try:
        err_color = (not getattr(args, "no_color", False)) and sys.stderr.isatty() and ("NO_COLOR" not in os.environ)
        print(format_startup_banner(Style(err_color)), file=sys.stderr)
        return args.func(args)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"\n✗ {tr('Ошибка', 'Error')}: {exc}", file=sys.stderr)
        print(_issue_hint(), file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - an unexpected error: keep the traceback, point at the issue tracker
        traceback.print_exc()
        print(_issue_hint(), file=sys.stderr)
        return 1


def _issue_hint() -> str:
    from contitool.report import ISSUES_PAGE

    return tr(
        f"Если причина непонятна — опишите проблему в GitHub Issues: {ISSUES_PAGE}\n"
        "Приложите журналы операции из папки contitool_runs (без дампов *.bin). В личные сообщения автору не пишите.",
        f"If the cause is unclear, open an issue on GitHub: {ISSUES_PAGE}\n"
        "Attach the operation logs from the contitool_runs folder (not the *.bin dumps). Please do not message the author.",
    )


if __name__ == "__main__":
    sys.exit(main())
