class YubikeySk < Formula
  desc "YubiKey FIDO2 SK provider for Apple's OpenSSH"
  homepage "https://github.com/giautm/yubikey-sk"
  url "https://github.com/giautm/yubikey-sk.git",
    tag:      "v0.1.0",
    revision: "HEAD"
  license "ISC"
  head "https://github.com/giautm/yubikey-sk.git", branch: "master"

  depends_on "libfido2"
  depends_on "openssl@3"
  depends_on :macos

  def install
    system "make",
      "FIDO2_PREFIX=#{Formula["libfido2"].opt_prefix}",
      "OPENSSL_PREFIX=#{Formula["openssl@3"].opt_prefix}",
      "PREFIX=#{prefix}"
    system "make", "install",
      "PREFIX=#{prefix}"
    include.install "sk-api.h"
  end

  def caveats
    <<~EOS
      To use this SK provider with SSH, add to your ~/.ssh/config:

        Host *
          SecurityKeyProvider #{lib}/libyubikey-sk.dylib
          IdentityAgent none

      Or set the environment variable:

        export SSH_SK_PROVIDER=#{lib}/libyubikey-sk.dylib

      Note: IdentityAgent none is required because Apple's ssh-agent
      does not support SK key operations.
    EOS
  end

  test do
    (testpath/"test.c").write <<~C
      #include <stdint.h>
      #include <stdio.h>
      #include <sk-api.h>
      int main(void) {
        uint32_t vers = sk_api_version();
        if ((vers & SSH_SK_VERSION_MAJOR_MASK) == SSH_SK_VERSION_MAJOR) {
          printf("0x%08x\\n", vers);
          return 0;
        }
        return 1;
      }
    C
    system ENV.cc, "-I#{include}", "-o", "test", "test.c",
      "#{lib}/libyubikey-sk.dylib"
    assert_match(/^0x000a0000$/, shell_output("./test"))
  end
end
