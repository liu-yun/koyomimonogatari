# Koyomimonogatari
Collect resources from [Koyomimonogatari app](https://play.google.com/store/apps/details?id=com.aniplex.koyomimonogatari).

Usage
---
Run `fetch.py`, and it will download the resources automatically.

`calendargen.py`, generates a `cache.dat` file. Put it into `/data/data/com.aniplex.koyomimonogatari/files/` and your calendar will be complete.

`calendarhelper.py` reads dates in `calendar.csv` and sync against the server. Example:
```
2016/01/01
2016/01/02
......
2016/01/25
```

`decoder.py` decodes the obfuscated strings in the Java source code.
