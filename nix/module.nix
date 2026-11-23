# services.ipv6ddns: ipv6ddns as a service of NixOS, with the limits its packages run it under.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.ipv6ddns;
  yaml = pkgs.formats.yaml { };
  configFile =
    if cfg.configFile != null then cfg.configFile else yaml.generate "ipv6ddns.yaml" cfg.settings;
in
{
  options.services.ipv6ddns = {
    enable = lib.mkEnableOption "ipv6ddns, which keeps DNS names for the devices of the network";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "ipv6ddns.packages.\${system}.default";
      description = "The ipv6ddns package to run.";
    };

    settings = lib.mkOption {
      type = yaml.type;
      default = { };
      example = lib.literalExpression ''
        {
          webserver.listen = [ "127.0.0.1:8053" ];
          tasks.server = {
            filter = [
              {
                self = true;
                ip.type = [ "global" ];
              }
            ];
            endpoints.cloudflare = [ "server" ];
          };
          credentials.cloudflare = {
            provider = "cloudflare";
            settings = {
              api_token = "''${CLOUDFLARE_TOKEN}";
              zone = "example.com";
            };
          };
        }
      '';
      description = ''
        The configuration of ipv6ddns, as its file has it: see
        <https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/reference/configuration.md>.
        Without tasks, it only discovers.

        It is written to the Nix store, which every user can read: keep a secret out of it,
        as `''${NAME}`, with the variable in {option}`environmentFile`, or as
        `''${file:/run/secrets/name}`, a file the service reads as root.

        The file is not written to, so a `homeassistant` block with `key_provisioning`
        needs its `key_provisioning_state_file` somewhere that is, as
        `/var/lib/ipv6ddns/homeassistant.state`.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/ipv6ddns/config.yaml";
      description = ''
        A configuration file to use as it is, in place of {option}`settings`: one kept outside
        the Nix store.
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/ipv6ddns.env";
      description = ''
        A file of `NAME=value` lines, the variables the configuration names as `''${NAME}`:
        its secrets, kept outside the Nix store.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # The two blocks a configuration must have, empty until given.
    services.ipv6ddns.settings = {
      tasks = lib.mkDefault { };
      credentials = lib.mkDefault { };
    };

    # The command, for its --version and its --live, and its manual page.
    environment.systemPackages = [ cfg.package ];

    systemd.services.ipv6ddns = {
      description = "ipv6ddns: DNS names for every device on your network, wherever its addresses move";
      documentation = [
        "man:ipv6ddns(1)"
        "https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/README.md"
      ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      # As packaging/ipv6ddns.service, which a test of the packages holds to discover under them:
      # root with two capabilities, raw sockets and the ports under 1024, and a file system it
      # can't write, but for its state.
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --config ${configFile}";
        Restart = "on-failure";
        RestartSec = "5s";
        # The updates running get 30 seconds to end, and then the process ends by itself.
        TimeoutStopSec = "40s";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;

        StateDirectory = "ipv6ddns";
        WorkingDirectory = "/var/lib/ipv6ddns";

        CapabilityBoundingSet = [
          "CAP_NET_RAW"
          "CAP_NET_BIND_SERVICE"
        ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
          "AF_PACKET"
          "AF_UNIX"
        ];
        SystemCallArchitectures = "native";
      };
    };
  };
}
