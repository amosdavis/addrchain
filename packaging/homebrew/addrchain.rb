class Addrchain < Formula
  desc "Blockchain-based network address management replacing DHCP"
  homepage "https://github.com/amosdavis/addrchain"
  url "https://github.com/amosdavis/addrchain/releases/download/v2.0.0/addrchain-2.0.0-darwin-amd64.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  version "2.0.0"

  depends_on "gcc" => :build

  def install
    # Compile daemon
    system ENV.cc, "-Wall", "-Wextra", "-Werror", "-std=c11", "-O2",
           "-DAC_VERSION_STR=\"#{version}\"",
           "-o", "addrd",
           "daemon/addrd.c", "daemon/addrd_sync.c", "daemon/addrd_vpn.c",
           *Dir["common/*.c"],
           "-Icommon"

    # Compile CLI
    system ENV.cc, "-Wall", "-Wextra", "-Werror", "-std=c11", "-O2",
           "-DAC_VERSION_STR=\"#{version}\"",
           "-o", "addrctl",
           "cli/addrctl.c",
           *Dir["common/*.c"],
           "-Icommon"

    sbin.install "addrd"
    bin.install "addrctl"
    etc.mkpath "addrchain"

    # Install documentation
    doc.install "README.md"
    doc.install Dir["spec/*.md"]
  end

  def post_install
    (var/"log/addrchain").mkpath
  end

  service do
    run [opt_sbin/"addrd", "--config-dir", etc/"addrchain"]
    keep_alive true
    log_path var/"log/addrchain/addrd.log"
    error_log_path var/"log/addrchain/addrd-error.log"
    working_dir var
  end

  test do
    assert_match "chain_height: 1", shell_output("#{bin}/addrctl status 2>&1")
  end
end
