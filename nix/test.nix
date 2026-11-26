# The module, in a machine of NixOS: its service runs, under its limits, and discovers the other
# machine of its network, by its MAC.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "ipv6ddns";

  nodes.machine = {
    imports = [ self.nixosModules.default ];
    services.ipv6ddns = {
      enable = true;
      settings = {
        listeners.web.listen = [ "http://127.0.0.1:8053" ];
        webservers.main.listeners = [ "web" ];
        discovery.ipv4.enabled = true;
      };
    };
    environment.systemPackages = [ pkgs.curl ];
  };

  nodes.peer = { };

  testScript = ''
    start_all()
    machine.wait_for_unit("ipv6ddns.service")
    machine.wait_until_succeeds("curl -fsS http://127.0.0.1:8053/healthz | grep -x ok")
    machine.succeed("ipv6ddns --version")
    machine.succeed("man -w ipv6ddns")

    # The other machine is on its network, and speaks there: it is found, at its MAC.
    peer.wait_for_unit("network.target")
    mac = peer.succeed("cat /sys/class/net/eth1/address").strip()
    peer.succeed("ping -c 3 machine >&2 || true")
    machine.wait_until_succeeds(
        f"curl -fsS http://127.0.0.1:8053/status.json | grep -i '{mac}'", timeout=180
    )

    # Its limits are the unit's of the packages, which it runs by: the two capabilities, and a
    # file system it can't write, but for its state.
    capabilities = machine.succeed("systemctl show ipv6ddns.service -p CapabilityBoundingSet --value").split()
    assert sorted(capabilities) == ["cap_net_bind_service", "cap_net_raw"], capabilities
    assert machine.succeed("systemctl show ipv6ddns.service -p ProtectSystem --value").strip() == "strict"
    assert machine.succeed("systemctl show ipv6ddns.service -p NoNewPrivileges --value").strip() == "yes"
    machine.succeed("systemctl cat ipv6ddns.service | grep -q 'man:ipv6ddns(1)'")
    machine.succeed("test -d /var/lib/ipv6ddns")

    # And nothing was refused to it.
    machine.fail(
        "journalctl -u ipv6ddns.service | grep -Ei 'not permitted|permission denied|read-only file system'"
    )
  '';
}
