DNSHawk Technitium zone files

Files:
- lab_test.zone
- corp_test.zone
- dev_test.zone
- office_test.zone

Each file defines one zone and five A records for the benign baseline test.
The IPs are example DNS records for the lab; no hosts need to exist at these addresses for DNS lookup testing.

In Technitium:
1. Add Zone -> Primary Zone.
2. Enter the matching zone name (e.g. lab.test).
3. Choose the corresponding .zone file in "Import Zone File (Optional)".
4. Click Add.
5. Repeat for all four zones.

Verify from Kali:
dig @192.168.111.1 web.lab.test A
dig @192.168.111.1 portal.corp.test A
dig @192.168.111.1 frontend.dev.test A
dig @192.168.111.1 printer.office.test A

If Technitium's import expects a different zone-file format/version, create the primary zone first and use the zone's import option or add the records through the UI.
