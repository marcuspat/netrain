class Netrain < Formula
  desc "Matrix-style network packet monitor with threat detection"
  homepage "https://github.com/marcuspat/netrain"
  url "https://github.com/marcuspat/netrain/archive/v0.2.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/marcuspat/netrain.git", branch: "main"

  depends_on "rust" => :build
  depends_on "libpcap"

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOS
      NetRain requires root privileges to capture network packets:
        sudo netrain

      To run in demo mode without root privileges:
        netrain --demo
    EOS
  end

  test do
    # Test that the binary runs and shows version
    assert_match "NetRain v#{version}", shell_output("#{bin}/netrain --version 2>&1", 1)
    
    # Test demo mode (doesn't require root)
    pid = fork { exec bin/"netrain", "--demo" }
    sleep 2
    Process.kill("TERM", pid)
    Process.wait(pid)
  end
end