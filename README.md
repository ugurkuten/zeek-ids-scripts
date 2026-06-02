# Zeek IDS Scripts

A small set of custom Zeek IDS scripts for detecting HTTP, UDP, and ICMP flood attacks. Each script uses Zeek's SumStats framework to count requests per source IP over a 2-minute epoch. A static threshold is applied during startup, and after the first epoch a dynamic baseline is stored per IP, triggering a notice if traffic exceeds 5x the baseline. These scripts were written as part of my bachelor thesis.

## Compatibility

Written and tested on Zeek 8.0. The scripts may also work on earlier versions with minor adjustments.

## Files

- `http_flood.zeek` - HTTP flood detection using SumStats, threshold and anomaly based
- `udp_flood.zeek` - UDP flood detection using SumStats, threshold and anomaly based
- `icmp_flood.zeek` - ICMP flood detection using SumStats, threshold and anomaly based

## Usage

### Option 1 - Run directly on a network interface

```bash
zeek -i <network-interface> -C http_flood.zeek
zeek -i <network-interface> -C udp_flood.zeek
zeek -i <network-interface> -C icmp_flood.zeek
```

### Option 2 - Load via local.zeek

1. Copy the `.zeek` files into your Zeek scripts directory (typically `/usr/local/zeek/share/zeek/site/`).
2. Add the following lines to your `local.zeek`:

```
@load http_flood
@load udp_flood
@load icmp_flood
```

3. Make sure Zeek is configured with the correct network interface.
4. Restart Zeek or reload the configuration:

```bash
zeekctl deploy
```

## Requirements

- Zeek 8.0
- The following Zeek frameworks (included by default):
  - `base/frameworks/sumstats`
  - `base/frameworks/notice`
  - `base/protocols/http`

## License

MIT
