# Koyomimonogatari
Collect resources from [Koyomimonogatari app](https://play.google.com/store/apps/details?id=com.aniplex.koyomimonogatari).

Usage
---
Run `fetch.py`, and it will download the resources automatically.

Run `calendargen.py`, it will generate a `cache.dat` file. Put it into `/data/data/com.aniplex.koyomimonogatari/files/` and your calendar will be complete.

`calendarhelper.py` reads dates in `calendar.csv` and sync against the server. See a sample:
```
2016/01/01
2016/01/02
......
```

`decoder.py` decodes the obfuscated strings in the Java source code.

WARNING
---
You will need a valid `user_id` in `fetch.ini`.

If you meet `403 Forbidden`, please retry with an IP in Japan.

License
---
GPLv3
