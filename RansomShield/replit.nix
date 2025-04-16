{pkgs}: {
  deps = [
    pkgs.wireshark
    pkgs.tcpdump
    pkgs.sox
    pkgs.imagemagickBig
    pkgs.glibcLocales
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.sqlite
    pkgs.dbus
    pkgs.zstd
    pkgs.freetype
    pkgs.fontconfig
    pkgs.libxkbcommon
    pkgs.postgresql
    pkgs.openssl
  ];
}
