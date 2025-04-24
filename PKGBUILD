# Maintainer: VHSgunzo <vhsgunzo.github.io>

pkgname='runimage-cpids'
pkgver='0.0.1'
pkgrel='1'
pkgdesc='A utility for tracking child processes of the runimage container'
url="https://github.com/VHSgunzo/runimage-cpids"
arch=('x86_64' 'aarch64')
license=('MIT')
options=(!strip)
source=("$url/releases/download/v$pkgver/cpids-${CARCH}")
sha256sums=('SKIP')

package() {
  install -Dm755 "cpids-${CARCH}" "${pkgdir}/var/RunDir/sharun/bin/cpids"
}
