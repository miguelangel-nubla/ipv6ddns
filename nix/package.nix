# The command, built from this source, with its manual page.
{
  lib,
  buildGoModule,
  installShellFiles,
  version,
}:

buildGoModule {
  pname = "ipv6ddns";
  inherit version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../config
      ../ddns
      ../internal
      ../pkg
      ../source
      ../packaging/ipv6ddns.1
      ../packaging/ipv6ddns.service
      (lib.fileset.fileFilter (file: file.hasExt "go") ../.)
    ];
  };

  # The hash of the modules go.sum names: tools/nix-test.sh --update writes it, after a change
  # of them, and nix flake check fails while it is behind.
  vendorHash = "sha256-x3cbSLy8kdxgR7WvLjgOC5bXfxKWjN83W+UEqGAFWzA=";

  subPackages = [ "cmd/ipv6ddns" ];

  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
    "-X main.commit=${version}"
    "-X main.date=1970-01-01T00:00:00Z"
  ];

  # The tests are CI's, which runs them where they have what they need: a network, and Python.
  doCheck = false;

  nativeBuildInputs = [ installShellFiles ];

  # The unit is the packages' own, with the command where Nix has it: the NixOS module runs it,
  # so that the limits of the service are written once.
  postInstall = ''
    installManPage packaging/ipv6ddns.1
    install -Dm644 packaging/ipv6ddns.service $out/lib/systemd/system/ipv6ddns.service
    substituteInPlace $out/lib/systemd/system/ipv6ddns.service \
      --replace-fail /usr/bin/ipv6ddns $out/bin/ipv6ddns
    install -Dm644 cmd/ipv6ddns/example.config.yaml $out/share/ipv6ddns/example.config.yaml
  '';

  meta = {
    description = "DNS names for every device on your network, wherever its addresses move";
    homepage = "https://github.com/miguelangel-nubla/ipv6ddns";
    license = lib.licenses.asl20;
    mainProgram = "ipv6ddns";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
