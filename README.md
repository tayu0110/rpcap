## 機能
パケットをキャプチャして、標準出力にダンプしたり、pcap形式のファイルに書き出すことができます。

## 使い方
- キャプチャ可能な全インタフェースでパケットをキャプチャし、標準出力にダンプする
```
$ rpcap
```
- インタフェースを絞ってパケットをキャプチャする
  - カンマ区切りで複数のインタフェースが指定できます
```
$ rpcap -i eth0,eth1
```
- pcap形式のファイルにキャプチャしたパケットを書き出す
```
$ rpcap -i eth0 -w packet.pcap
```
- ヘルプを出す
```
$ rpcap -h
```

## ライセンス
このソフトウェアはMITライセンスのもと公開されています。LICENSEをご覧ください。
また、このソフトウェアでは以下のライブラリを利用させていただいています。
- exitcode(Apache-2.0)
- chrono(MIT/Apache-2.0)
- clap(MIT/Apache-2.0)
- libpnet(MIT/Apache-2.0)
- serde(MIT/Apache-2.0)
- serde_bytes(MIT/Apache-2.0)
- bincode(MIT)
- byteorder(MIT/Unlicense)

## License
This software is released under the MIT License, see LICENSE.
The following libraries are used in this software.
- exitcode(Apache-2.0)
- chrono(MIT/Apache-2.0)
- clap(MIT/Apache-2.0)
- libpnet(MIT/Apache-2.0)
- serde(MIT/Apache-2.0)
- serde_bytes(MIT/Apache-2.0)
- bincode(MIT)
- byteorder(MIT/Unlicense)
