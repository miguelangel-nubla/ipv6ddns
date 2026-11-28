# services.ipv6ddns: ipv6ddns as a service of NixOS, by the unit its packages have.
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
          listeners.web.listen = [ "http://127.0.0.1:8053" ];
          webservers.main.listeners = [ "web" ];
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

        Its `state_dir`, where ipv6ddns keeps what it writes, is `/var/lib/ipv6ddns`
        unless given.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/ipv6ddns/config.yaml";
      description = ''
        A configuration file to use as it is, in place of {option}`settings`: one kept outside
        the Nix store. The service can't write beside it: give it
        `state_dir: /var/lib/ipv6ddns`, for what ipv6ddns keeps.
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
      # What it writes goes to the service's state directory: its default is beside the
      # configuration, which is in the store.
      state_dir = lib.mkDefault "/var/lib/ipv6ddns";
    };

    # The command, for its --version and its --live, and its manual page.
    environment.systemPackages = [ cfg.package ];

    # The unit is the one of the packages, packaging/ipv6ddns.service, which the package brings
    # with it: its limits are written there, once, and a test of the packages holds the service
    # to discover under them. Here is only what NixOS has otherwise.
    systemd.packages = [ cfg.package ];
    systemd.services.ipv6ddns = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        # In place of the unit's, with the configuration of this module.
        ExecStart = [
          ""
          "${lib.getExe cfg.package} --config ${configFile}"
        ];
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        # The state is not beside the configuration, which is in the store: the unit's folder
        # to write to, /etc/ipv6ddns, is not there, and this one is in its place.
        ReadWritePaths = [ "" ];
        StateDirectory = "ipv6ddns";
        WorkingDirectory = "/var/lib/ipv6ddns";
      };
    };
  };
}
