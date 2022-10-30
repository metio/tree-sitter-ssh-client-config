module.exports = grammar({
  name: 'sshclientconfig',

  extras: $ => [
    $.comment,
    /\s/,
    /\\\r?\n/,
    /\\( |\t|\v|\f)/
  ],

  rules: {
    client_config: $ => repeat($._option),

    _option: $ => choice(
        $.host,
        $.match,
        $.add_keys_to_agent,
        $.address_family,
        $.batch_mode,
        $.bind_address,
        $.bind_interface,
        $.canonical_domains,
        $.canonicalize_fallback_local,
        $.canonicalize_hostname,
        $.canonicalize_max_dots,
        $.canonicalize_permitted_cnames,
        $.ca_signature_algorithms,
        $.certificate_file,
        $.challenge_response_authentication,
        $.check_host_ip,
        $.cipher,
        $.ciphers,
        $.clear_all_forwardings,
        $.compression,
        $.connection_attempts,
        $.connect_timeout,
        $.control_master,
        $.control_path,
        $.control_persist,
        $.dynamic_forward,
        $.enable_ssh_keysign,
        $.escape_char,
        $.exit_on_forward_failure,
        $.fingerprint_hash,
        $.fork_after_authentication,
        $.forward_agent,
        $.forward_x11,
        $.forward_x11_timeout,
        $.forward_x11_trusted,
        $.gateway_ports,
        $.global_known_hosts_file,
        $.gssapi_authentication,
        $.gssapi_client_identity,
        $.gssapi_delegate_credentials,
        $.gssapi_key_exchange,
        $.gssapi_renewal_forces_rekey,
        $.gssapi_server_identity,
        $.gssapi_trust_dns,
        $.gssapi_kex_algorithms,
        $.hash_known_hosts,
        $.hostbased_accepted_algorithms,
        $.hostbased_authentication,
        $.host_key_algorithms,
        $.host_key_alias,
        $.hostname,
        $.identities_only,
        $.identity_agent,
        $.identity_file,
        $.ignore_unknown,
        $.include,
        $.ip_qos,
        $.kbd_interactive_authentication,
        $.kbd_interactive_devices,
        $.kex_algorithms,
        $.known_hosts_command,
        $.local_command,
        $.local_forward,
        $.log_level,
        $.log_verbose,
        $.macs,
        $.no_host_authentication_for_localhost,
        $.number_of_password_prompts,
        $.password_authentication,
        $.permit_local_command,
        $.permit_remote_open,
        $.pkcs11_provider,
        $.port,
        $.preferred_authentications,
        $.protocol,
        $.proxy_command,
        $.proxy_jump,
        $.proxy_use_fdpass,
        $.pubkey_accepted_algorithms,
        $.pubkey_accepted_key_types,
        $.pubkey_authentication,
        $.rekey_limit,
        $.remote_command,
        $.remote_forward,
        $.request_tty,
        $.revoked_host_keys,
        $.security_key_provider,
        $.send_env,
        $.server_alive_count_max,
        $.server_alive_interval,
        $.session_type,
        $.set_env,
        $.stdin_null,
        $.stream_local_bind_mask,
        $.stream_local_bind_unlink,
        $.strict_host_key_checking,
        $.syslog_facility,
        $.tcp_keep_alive,
        $.keep_alive,
        $.tunnel,
        $.tunnel_device,
        $.update_host_keys,
        $.use_keychain,
        $.user,
        $.user_known_hosts_file,
        $.verify_host_key_dns,
        $.visual_host_key,
        $.xauth_location,
    ),

    comment: $ => token(prec(-10, /#.*/)),
    number: $ => /[1234567890]+/,
    boolean: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
    ),
    pattern: $ => /.*/,
    time_format: $ => /[1234567890]+[sSmMhHdDwW]?/,

    host: $ => option(
        'Host',
        $.host_value
    ),
    host_value: $ => alias($.pattern, "host_value"),

    match: $ => option(
        'Match',
        $.match_value
    ),
    match_value: $ => alias($.pattern, "match_value"),

    add_keys_to_agent: $ => option(
        'AddKeysToAgent',
        $.add_keys_to_agent_value
    ),
    add_keys_to_agent_value: $ => alias($.boolean, "add_keys_to_agent_value"),

    address_family: $ => option(
        'AddressFamily',
        $.address_family_value
    ),
    address_family_value: $ => choice(
        ignoreCase('any'),
        ignoreCase('inet'),
        ignoreCase('inet6'),
    ),

    batch_mode: $ => option(
        'BatchMode',
        $.batch_mode_value
    ),
    batch_mode_value: $ => alias($.boolean, "batch_mode_value"),

    bind_address: $ => option(
        'BindAddress',
        $.bind_address_value
    ),
    bind_address_value: $ => /.*/,

    bind_interface: $ => option(
        'BindInterface',
        $.bind_interface_value
    ),
    bind_interface_value: $ => /.*/,

    canonical_domains: $ => option(
        'CanonicalDomains',
        $.canonical_domains_value
    ),
    canonical_domains_value: $ => /.*/,

    canonicalize_fallback_local: $ => option(
        'CanonicalizeFallbackLocal',
        $.canonicalize_fallback_local_value
    ),
    canonicalize_fallback_local_value: $ => alias($.boolean,
        "canonicalize_fallback_local_value"),

    canonicalize_hostname: $ => option(
        'CanonicalizeHostname',
        $.canonicalize_hostname_value
    ),
    canonicalize_hostname_value: $ => choice(
        ignoreCase('true'),
        ignoreCase('yes'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('always'),
        'none'
    ),

    canonicalize_max_dots: $ => option(
        'CanonicalizeMaxDots',
        $.canonicalize_max_dots_value
    ),
    canonicalize_max_dots_value: $ => alias($.number,
        "canonicalize_max_dots_value"),

    canonicalize_permitted_cnames: $ => option(
        'CanonicalizePermittedCNAMEs',
        $.canonicalize_permitted_cnames_value
    ),
    canonicalize_permitted_cnames_value: $ => /.*/,

    ca_signature_algorithms: $ => option(
        'CASignatureAlgorithms',
        $.ca_signature_algorithms_value
    ),
    ca_signature_algorithms_value: $ => /.*/,

    certificate_file: $ => option(
        'CertificateFile',
        $.certificate_file_value
    ),
    certificate_file_value: $ => /.*/,

    challenge_response_authentication: $ => option(
        'ChallengeResponseAuthentication',
        $.challenge_response_authentication_value
    ),
    challenge_response_authentication_value: $ => alias($.boolean,
        "challenge_response_authentication_value"),

    check_host_ip: $ => option(
        'CheckHostIP',
        $.check_host_ip_value
    ),
    check_host_ip_value: $ => alias($.boolean, "check_host_ip_value"),

    ciphers: $ => option(
        'Ciphers',
        $.ciphers_value
    ),
    ciphers_value: $ => /.*/,

    cipher: $ => option(
        'Cipher',
        $.cipher_value
    ),
    cipher_value: $ => /.*/,

    clear_all_forwardings: $ => option(
        'ClearAllForwardings',
        $.clear_all_forwardings_value
    ),
    clear_all_forwardings_value: $ => alias($.boolean,
        "clear_all_forwardings_value"),

    compression: $ => option(
        'Compression',
        $.compression_value
    ),
    compression_value: $ => alias($.boolean, "compression_value"),

    connection_attempts: $ => option(
        'ConnectionAttempts',
        $.connection_attempts_value
    ),
    connection_attempts_value: $ => alias($.number,
        "connection_attempts_value"),

    connect_timeout: $ => option(
        'ConnectTimeout',
        $.connect_timeout_value
    ),
    connect_timeout_value: $ => alias($.number, "connect_timeout_value"),

    control_master: $ => option(
        'ControlMaster',
        $.control_master_value
    ),
    control_master_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('ask'),
        ignoreCase('auto'),
        ignoreCase('autoask'),
    ),

    control_path: $ => option(
        'ControlPath',
        $.control_path_value
    ),
    control_path_value: $ => /.*/,

    control_persist: $ => option(
        'ControlPersist',
        $.control_persist_value
    ),
    control_persist_value: $ => alias(choice($.boolean, $.time_format),
        'control_persist_value'),

    dynamic_forward: $ => option(
        'DynamicForward',
        $.dynamic_forward_value
    ),
    dynamic_forward_value: $ => /.*/,

    enable_ssh_keysign: $ => option(
        'EnableSSHKeysign',
        $.enable_ssh_keysign_value
    ),
    enable_ssh_keysign_value: $ => alias($.boolean, "enable_ssh_keysign_value"),

    escape_char: $ => option(
        'EscapeChar',
        $.escape_char_value
    ),
    escape_char_value: $ => choice('none', /(\^\w|[^\^])/),

    exit_on_forward_failure: $ => option(
        'ExitOnForwardFailure',
        $.exit_on_forward_failure_value
    ),
    exit_on_forward_failure_value: $ => alias($.boolean,
        "exit_on_forward_failure_value"),

    fingerprint_hash: $ => option(
        'FingerprintHash',
        $.fingerprint_hash_value
    ),
    fingerprint_hash_value: $ => choice('md5', 'sha256'),

    fork_after_authentication: $ => option(
        'ForkAfterAuthentication',
        $.fork_after_authentication_value
    ),
    fork_after_authentication_value: $ => alias($.boolean,
        "fork_after_authentication_value"),

    forward_agent: $ => option(
        'ForwardAgent',
        $.forward_agent_value
    ),
    forward_agent_value: $ => /.*/,

    forward_x11: $ => option(
        'ForwardX11',
        $.forward_x11_value
    ),
    forward_x11_value: $ => alias($.boolean, "forward_x11_value"),

    forward_x11_timeout: $ => option(
        'ForwardX11Timeout',
        $.forward_x11_timeout_value
    ),
    forward_x11_timeout_value: $ => alias($.time_format,
        "forward_x11_timeout_value"),

    forward_x11_trusted: $ => option(
        'ForwardX11Trusted',
        $.forward_x11_trusted_value
    ),
    forward_x11_trusted_value: $ => alias($.boolean,
        "forward_x11_trusted_value"),

    gateway_ports: $ => option(
        'GatewayPorts',
        $.gateway_ports_value
    ),
    gateway_ports_value: $ => alias($.boolean, "gateway_ports_value"),

    global_known_hosts_file: $ => option(
        'GlobalKnownHostsFile',
        $.global_known_hosts_file_value
    ),
    global_known_hosts_file_value: $ => /.*/,

    gssapi_authentication: $ => option(
        'GSSAPIAuthentication',
        $.gssapi_authentication_value
    ),
    gssapi_authentication_value: $ => alias($.boolean,
        "gssapi_authentication_value"),

    gssapi_client_identity: $ => option(
        'GSSAPIClientIdentity',
        $.gssapi_client_identity_value
    ),
    gssapi_client_identity_value: $ => /.*/,

    gssapi_delegate_credentials: $ => option(
        'GSSAPIDelegateCredentials',
        $.gssapi_delegate_credentials_value
    ),
    gssapi_delegate_credentials_value: $ => alias($.boolean,
        "gssapi_delegate_credentials_value"),

    gssapi_key_exchange: $ => option(
        'GSSAPIKeyExchange',
        $.gssapi_key_exchange_value
    ),
    gssapi_key_exchange_value: $ => alias($.boolean,
        "gssapi_key_exchange_value"),

    gssapi_renewal_forces_rekey: $ => option(
        'GSSAPIRenewalForcesRekey',
        $.gssapi_renewal_forces_rekey_value
    ),
    gssapi_renewal_forces_rekey_value: $ => alias($.boolean,
        "gssapi_renewal_forces_rekey_value"),

    gssapi_server_identity: $ => option(
        'GSSAPIServerIdentity',
        $.gssapi_server_identity_value
    ),
    gssapi_server_identity_value: $ => /.*/,

    gssapi_trust_dns: $ => option(
        'GSSAPITrustDns',
        $.gssapi_trust_dns_value
    ),
    gssapi_trust_dns_value: $ => alias($.boolean, "gssapi_trust_dns_value"),

    gssapi_kex_algorithms: $ => option(
        'GSSAPIKexAlgorithms',
        $.gssapi_kex_algorithms_value
    ),
    gssapi_kex_algorithms_value: $ => /.*/,

    hash_known_hosts: $ => option(
        'HashKnownHosts',
        $.hash_known_hosts_value
    ),
    hash_known_hosts_value: $ => alias($.boolean, "hash_known_hosts_value"),

    hostbased_accepted_algorithms: $ => option(
        'HostbasedAcceptedAlgorithms',
        $.hostbased_accepted_algorithms_value
    ),
    hostbased_accepted_algorithms_value: $ => /.*/,

    hostbased_authentication: $ => option(
        'HostbasedAuthentication',
        $.hostbased_authentication_value
    ),
    hostbased_authentication_value: $ => alias($.boolean,
        "hostbased_authentication_value"),

    host_key_algorithms: $ => option(
        'HostKeyAlgorithms',
        $.host_key_algorithms_value
    ),
    host_key_algorithms_value: $ => /.*/,

    host_key_alias: $ => option(
        'HostKeyAlias',
        $.host_key_alias_value
    ),
    host_key_alias_value: $ => /.*/,

    hostname: $ => option(
        'Hostname',
        $.hostname_value
    ),
    hostname_value: $ => /.*/,

    identities_only: $ => option(
        'IdentitiesOnly',
        $.identities_only_value
    ),
    identities_only_value: $ => alias($.boolean, "identities_only_value"),

    identity_agent: $ => option(
        'IdentityAgent',
        $.identity_agent_value
    ),
    identity_agent_value: $ => /.*/,

    identity_file: $ => option(
        'IdentityFile',
        $.identity_file_value
    ),
    identity_file_value: $ => /.*/,

    ignore_unknown: $ => option(
        'IgnoreUnknown',
        $.ignore_unknown_value
    ),
    ignore_unknown_value: $ => /.*/,

    include: $ => option(
        'Include',
        $.include_value
    ),
    include_value: $ => /.*/,

    ip_qos: $ => option(
        'IPQoS',
        $.ip_qos_value
    ),
    ip_qos_value: $ => alias(
        choice('af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32',
            'af33', 'af41', 'af42', 'af43', 'cs0', 'cs1', 'cs2', 'cs3', 'cs4',
            'cs5', 'cs6', 'cs7', 'ef', 'le', 'lowdelay', 'throughput',
            'reliability', 'none', $.number), 'ip_qos_value'),

    kbd_interactive_authentication: $ => option(
        'KbdInteractiveAuthentication',
        $.kbd_interactive_authentication_value
    ),
    kbd_interactive_authentication_value: $ => alias($.boolean,
        "kbd_interactive_authentication_value"),

    kbd_interactive_devices: $ => option(
        'KbdInteractiveDevices',
        $.kbd_interactive_devices_value
    ),
    kbd_interactive_devices_value: $ => /.*/,

    kex_algorithms: $ => option(
        'KexAlgorithms',
        $.kex_algorithms_value
    ),
    kex_algorithms_value: $ => /.*/,

    known_hosts_command: $ => option(
        'KnownHostsCommand',
        $.known_hosts_command_value
    ),
    known_hosts_command_value: $ => /.*/,

    local_command: $ => option(
        'LocalCommand',
        $.local_command_value
    ),
    local_command_value: $ => /.*/,

    local_forward: $ => option(
        'LocalForward',
        $.local_forward_value
    ),
    local_forward_value: $ => /.*/,

    log_level: $ => option(
        'LogLevel',
        $.log_level_value
    ),
    log_level_value: $ => choice(
        ignoreCase('quiet'),
        ignoreCase('fatal'),
        ignoreCase('error'),
        ignoreCase('info'),
        ignoreCase('verbose'),
        ignoreCase('debug'),
        ignoreCase('debug1'),
        ignoreCase('debug2'),
        ignoreCase('debug3'),
    ),

    log_verbose: $ => option(
        'LogVerbose',
        $.log_verbose_value
    ),
    log_verbose_value: $ => /.*/,

    macs: $ => option(
        'MACs',
        $.macs_value
    ),
    macs_value: $ => /.*/,

    no_host_authentication_for_localhost: $ => option(
        'NoHostAuthenticationForLocalhost',
        $.no_host_authentication_for_localhost_value
    ),
    no_host_authentication_for_localhost_value: $ => alias($.boolean,
        "no_host_authentication_for_localhost_value"),

    number_of_password_prompts: $ => option(
        'NumberOfPasswordPrompts',
        $.number_of_password_prompts_value
    ),
    number_of_password_prompts_value: $ => alias($.number,
        "number_of_password_prompts_value"),

    password_authentication: $ => option(
        'PasswordAuthentication',
        $.password_authentication_value
    ),
    password_authentication_value: $ => alias($.boolean,
        "password_authentication_value"),

    permit_local_command: $ => option(
        'PermitLocalCommand',
        $.permit_local_command_value
    ),
    permit_local_command_value: $ => alias($.boolean,
        "permit_local_command_value"),

    permit_remote_open: $ => option(
        'PermitRemoteOpen',
        $.permit_remote_open_value
    ),
    permit_remote_open_value: $ => /.*/,

    pkcs11_provider: $ => option(
        'PKCS11Provider',
        $.pkcs11_provider_value
    ),
    pkcs11_provider_value: $ => /.*/,

    port: $ => option(
        'Port',
        $.port_value
    ),
    port_value: $ => alias($.number, "port_value"),

    preferred_authentications: $ => option(
        'PreferredAuthentications',
        $.preferred_authentications_value
    ),
    preferred_authentications_value: $ => /.*/,

    protocol: $ => option(
        'Protocol',
        $.protocol_value
    ),
    protocol_value: $ => choice('1', '2'),

    proxy_command: $ => option(
        'ProxyCommand',
        $.proxy_command_value
    ),
    proxy_command_value: $ => /.*/,

    proxy_jump: $ => option(
        'ProxyJump',
        $.proxy_jump_value
    ),
    proxy_jump_value: $ => /.*/,

    proxy_use_fdpass: $ => option(
        'ProxyUseFdpass',
        $.proxy_use_fdpass_value
    ),
    proxy_use_fdpass_value: $ => alias($.boolean, "proxy_use_fdpass_value"),

    pubkey_accepted_algorithms: $ => option(
        'PubkeyAcceptedAlgorithms',
        $.pubkey_accepted_algorithms_value
    ),
    pubkey_accepted_algorithms_value: $ => /.*/,

    pubkey_accepted_key_types: $ => option(
        'PubkeyAcceptedKeyTypes',
        $.pubkey_accepted_key_types_value
    ),
    pubkey_accepted_key_types_value: $ => /.*/,

    pubkey_authentication: $ => option(
        'PubkeyAuthentication',
        $.pubkey_authentication_value
    ),
    pubkey_authentication_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('unbound'),
        ignoreCase('host-bound'),
    ),

    rekey_limit: $ => option(
        'RekeyLimit',
        $.rekey_limit_value
    ),
    rekey_limit_value: $ => /.*/,

    remote_command: $ => option(
        'RemoteCommand',
        $.remote_command_value
    ),
    remote_command_value: $ => /.*/,

    remote_forward: $ => option(
        'RemoteForward',
        $.remote_forward_value
    ),
    remote_forward_value: $ => /.*/,

    request_tty: $ => option(
        'RequestTTY',
        $.request_tty_value
    ),
    request_tty_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('auto'),
        ignoreCase('force'),
    ),

    revoked_host_keys: $ => option(
        'RevokedHostKeys',
        $.revoked_host_keys_value
    ),
    revoked_host_keys_value: $ => /.*/,

    security_key_provider: $ => option(
        'SecurityKeyProvider',
        $.security_key_provider_value
    ),
    security_key_provider_value: $ => /.*/,

    send_env: $ => option(
        'SendEnv',
        $.send_env_value
    ),
    send_env_value: $ => /.*/,

    server_alive_count_max: $ => option(
        'ServerAliveCountMax',
        $.server_alive_count_max_value
    ),
    server_alive_count_max_value: $ => alias($.number,
        "server_alive_count_max_value"),

    server_alive_interval: $ => option(
        'ServerAliveInterval',
        $.server_alive_interval_value
    ),
    server_alive_interval_value: $ => alias($.number,
        "server_alive_interval_value"),

    session_type: $ => option(
        'SessionType',
        $.session_type_value
    ),
    session_type_value: $ => choice(
        ignoreCase('none'),
        ignoreCase('subsystem'),
        ignoreCase('default')
    ),

    set_env: $ => option(
        'SetEnv',
        $.set_env_value
    ),
    set_env_value: $ => /.*/,

    stdin_null: $ => option(
        'StdinNull',
        $.stdin_null_value
    ),
    stdin_null_value: $ => alias($.boolean, "stdin_null_value"),

    stream_local_bind_mask: $ => option(
        'StreamLocalBindMask',
        $.stream_local_bind_mask_value
    ),
    stream_local_bind_mask_value: $ => /.*/,

    stream_local_bind_unlink: $ => option(
        'StreamLocalBindUnlink',
        $.stream_local_bind_unlink_value
    ),
    stream_local_bind_unlink_value: $ => alias($.boolean,
        "stream_local_bind_unlink_value"),

    strict_host_key_checking: $ => option(
        'StrictHostKeyChecking',
        $.strict_host_key_checking_value
    ),
    strict_host_key_checking_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('off'),
        ignoreCase('ask'),
        ignoreCase('accept-new'),
    ),

    syslog_facility: $ => option(
        'SyslogFacility',
        $.syslog_facility_value
    ),
    syslog_facility_value: $ => choice('DAEMON', 'USER', 'AUTH', 'LOCAL0',
        'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7'),

    tcp_keep_alive: $ => option(
        'TCPKeepAlive',
        $.tcp_keep_alive_value
    ),
    tcp_keep_alive_value: $ => alias($.boolean, "tcp_keep_alive_value"),

    keep_alive: $ => option(
        'KeepAlive',
        $.keep_alive_value
    ),
    keep_alive_value: $ => alias($.boolean, "keep_alive_value"),

    tunnel: $ => option(
        'Tunnel',
        $.tunnel_value
    ),
    tunnel_value: $ => choice('yes', 'no', 'point-to-point', 'ethernet'),

    tunnel_device: $ => option(
        'TunnelDevice',
        $.tunnel_device_value
    ),
    tunnel_device_value: $ => /.*/,

    update_host_keys: $ => option(
        'UpdateHostKeys',
        $.update_host_keys_value
    ),
    update_host_keys_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('ask'),
    ),

    use_keychain: $ => option(
        'UseKeychain',
        $.use_keychain_value
    ),
    use_keychain_value: $ => alias($.boolean, "use_keychain_value"),

    user: $ => option(
        'User',
        $.user_value
    ),
    user_value: $ => /.*/,

    user_known_hosts_file: $ => option(
        'UserKnownHostsFile',
        $.user_known_hosts_file_value
    ),
    user_known_hosts_file_value: $ => /.*/,

    verify_host_key_dns: $ => option(
        'VerifyHostKeyDNS',
        $.verify_host_key_dns_value
    ),
    verify_host_key_dns_value: $ => choice(
        ignoreCase('yes'),
        ignoreCase('true'),
        ignoreCase('no'),
        ignoreCase('false'),
        ignoreCase('ask'),
    ),

    visual_host_key: $ => option(
        'VisualHostKey',
        $.visual_host_key_value
    ),
    visual_host_key_value: $ => alias($.boolean, "visual_host_key_value"),

    xauth_location: $ => option(
        'XAuthLocation',
        $.xauth_location_value
    ),
    xauth_location_value: $ => /.*/,

  }
});

function option(name, value) {
  return seq(
      keyword(name),
      optional('='),
      optional('"'),
      value,
      optional('"'),
  )
}

function keyword(word) {
  return alias(reserved(ignoreCase(word)), word)
}

function ignoreCase(word) {
  return new RegExp(caseInsensitive(word))
}

function reserved(regex) {
  return token(prec(1, regex))
}

function caseInsensitive(word) {
  return word
      .split('')
      .map(letter => `[${letter.toLowerCase()}${letter.toUpperCase()}]`)
      .join('')
}
