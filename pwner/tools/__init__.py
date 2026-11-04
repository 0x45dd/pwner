"""Network pentest tools for pwner — nmap wrapper + DNS/banner/HTTP + safety rails.

The authorization boundary is the scope guard: build_dispatch wraps EVERY tool with
_enforce_scope, which rejects any host or network argument outside the operator's
authorized target before the tool body runs. Tools are in-scope-by-default, so one that
forgets its own _require_scope call is still guarded. High-impact actions (brute-force,
exploitation) additionally pass a consent gate, and intrusive NSE categories (brute, dos,
exploit) are block-listed in the generic run_nmap escape hatch.

`core` owns the boundary and the registry; every other module imports from it and from
nothing else, so the dependency graph is a star with no cycles:

    core      scope guard · consent gate · @tool registry · dispatch · ScanContext
    nmap      port/service/vuln/OS scans, host discovery, nuclei
    web       scheme probing, endpoint discovery, raw HTTP requests
    net       DNS, banners, raw TCP, SNMP, FTP
    ad        Active Directory + credentialed execution (impacket/netexec/kerbrute/...)
    pci       PCI DSS 11.4.5/11.4.6 segmentation test, 11.4.4 exposure retest
    session   reverse-shell listener, exfil channel, shell_exec
    target    operator phrase -> authorized scope
    report    findings, ledger, dependency status, the agent's brief

Importing this package imports all of them, and that is what fills the registry: a
submodule nobody imports registers no tools, so its tools would silently disappear from
the agent's toolset. tests/test_registry.py pins the tool count so that cannot pass
unnoticed. The re-exports below keep `from .tools import X` working for every name the
module exposed when it was one flat file.
"""
from __future__ import annotations

from .ad import (  # noqa: F401
    _auth_principal,
    _clean_nxc,
    _hash_hunt,
    _mktemp_lines,
    _run_cli,
    adcs_find,
    asrep_roast,
    bloodhound_collect,
    cred_check,
    dc_vuln_check,
    hash_crack,
    hydra_brute,
    kerberoast,
    kerbrute_userenum,
    ldap_enum,
    password_spray,
    rid_brute,
    secretsdump,
    smb_get,
    smb_shares,
    ssh_exec,
    win_exec,
)
from .core import (  # noqa: F401
    _NUCLEI_CATEGORIES,
    _REGISTRY,
    _SCOPED_ARG_NAMES,
    ALLOWED_SCRIPT_ARGS_HINT,
    BLOCKED_SCRIPT_CATEGORIES,
    DEFAULT_PASSWORDS,
    DEFAULT_USERS,
    HYDRA_BIN,
    NMAP_BIN,
    NUCLEI_BIN,
    PORT_PRESETS,
    SNMPWALK_BIN,
    OperatorChannel,
    ScanContext,
    ToolError,
    _ask_consent,
    _consent,
    _consent_granted,
    _enforce_scope,
    _extract_strings,
    _guarded,
    _hosts_in_value,
    _impacket,
    _is_root,
    _literal_in_scope,
    _netexec,
    _nuclei_template_args,
    _nuclei_template_dir,
    _require_scope,
    _resolve_ips,
    _scan_creds,
    _source_ip_for,
    _Tool,
    _which_any,
    build_dispatch,
    expand_hosts,
    has_hydra,
    has_nuclei,
    in_scope,
    scope_exempt_tools,
    tool,
    tool_schemas,
)
from .net import (  # noqa: F401
    banner_grab,
    dns_enum,
    ftp_anon,
    ftp_get,
    snmp_check,
    tcp_send,
)
from .nmap import (  # noqa: F401
    _guard_nmap_args,
    _parse_nmap_xml,
    _ports_arg_list,
    _run_nmap,
    _summarize,
    nuclei_scan,
    os_detect,
    ping_sweep,
    port_scan,
    run_nmap,
    service_detect,
    smb_enum,
    ssl_info,
    vuln_scan,
)
from .pci import (  # noqa: F401
    DEFAULT_CDE_PORTS,
    _file_reachable_findings,
    _gate,
    _probe,
    _require_cde_scope,
    classify_error,
    parse_ports,
    pci_retest,
    segmentation_test,
    segmentation_verdict,
    summarise_segmentation,
)
from .report import (  # noqa: F401
    _env_note,
    brief,
    dependency_status,
    exploit_search,
    get_findings,
    ledger,
    missing_tool_names,
    note,
    report_finding,
    request_consent,
)
from .session import (  # noqa: F401
    ExploitState,
    _b64_maybe,
    _exploit,
    attacker_info,
    exfil,
    listener,
    shell_exec,
)
from .target import (  # noqa: F401
    _LOCAL_WORDS,
    _iface_ipv4_prefix,
    _primary_ipv4,
    resolve_target_spec,
    set_target,
)
from .web import (  # noqa: F401
    _COMMON_PATHS,
    _collected_set_cookie,
    _parse_html,
    _scheme_for,
    _sync_cookies,
    _tls_handshake_ok,
    content_discovery,
    http_download,
    http_probe,
    summarise_probes,
    web_request,
)
