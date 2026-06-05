# CRS Tuning Note

Evidence screenshot:

`screenshots/crs paranoia level changed.png`

The screenshot shows editing of:

`/etc/modsecurity/crs/crs-setup.conf`

Visible setting:

```apache
setvar:tx.paranoia_level=2
```

## Meaning

Raising the CRS paranoia level increases inspection strictness and can improve detection coverage. It may also increase false positives, so tests should be repeated after tuning.

## Configuration Export Commands

Export the final configuration from the VM:

```bash
sudo cp /etc/modsecurity/crs/crs-setup.conf Evidence/configs/crs-setup.conf
sudo cp /etc/modsecurity/modsecurity.conf Evidence/configs/modsecurity.conf
```
