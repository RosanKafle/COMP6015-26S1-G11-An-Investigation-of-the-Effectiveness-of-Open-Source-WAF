# Final CRS Configuration Note

Evidence screenshot:

`screenshots/crs paranoia level changed.png`

Observed setting:

```apache
setvar:tx.paranoia_level=2
```

Interpretation:

- CRS paranoia level was changed to 2.
- This increases rule strictness and can improve detection coverage.
- It should be tested against normal traffic to identify false positives.

Configuration export commands:

```bash
sudo cp /etc/modsecurity/crs/crs-setup.conf ./week10_final_crs-setup.conf
sudo cp /etc/modsecurity/modsecurity.conf ./week10_final_modsecurity.conf
apache2ctl -M > ./week10_apache_modules.txt
dpkg -l | grep -Ei "apache2|modsecurity|coreruleset|crs" > ./week10_package_versions.txt
```
