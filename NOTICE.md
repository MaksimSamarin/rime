# Attribution

Rime is a fork of [Marzban](https://github.com/Gozargah/Marzban), based on
v0.8.4 / commit 7f396db. The original AGPL-3.0 LICENSE, copyright notices and Git
history are retained. Rime additions: MaksimSamarin.

`core-patches/` targets [Hysteria](https://github.com/apernet/hysteria), app/v2.12.3.
Retain Hysteria's upstream MIT license/notices with redistributed patched source
and binaries. Xray and Marzban Node remain upstream components under their licenses.

The entry-server forwarding runtime uses GOST v3.3.3 from go-gost/gost under
its MIT license. The image includes its original license at
`/opt/rime-relay/LICENSE.gost`. The runtime is downloaded during the image build
and verified against the archive and executable SHA-256 values in
`scripts/vendor_relay.py`.

The qualified native-node image and the panel's payload probe use
[Xray-core v26.6.1](https://github.com/XTLS/Xray-core/releases/tag/v26.6.1)
under its upstream MPL-2.0 license. Its archive and executable SHA-256 pins are
in `scripts/vendor_xray.py`. The original release license is included at
`/opt/rime-xray/LICENSE.xray` in the native image and
`/opt/rime-probe/LICENSE.xray` in the panel image.

Names, environment variables, tables and API paths containing `marzban`, `hy2`
or `fleet` may remain for compatibility. They do not imply upstream endorsement.
