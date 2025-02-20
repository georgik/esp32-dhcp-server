# ESP32-S3 DHCP sever

## Configuration

Rename files in assets directory:
 - `dhcp_reservations_sample.json` to `dhcp_reservations.json`
 - `assets/wifi_config_sample.json` to `assets/wifi_config.json`

Update values in the configuration files.

## Build

```
idf.py build flash monitor
```

