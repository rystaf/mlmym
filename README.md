# mlmym
a familiar desktop experience for [lemmy](https://join-lemmy.org).

![screenshot](https://raw.githubusercontent.com/rystaf/mlmym/main/screenshot.png?raw=true)

### deployment

```bash
docker run -it -p "8080:8080" ghcr.io/rystaf/mlmym:latest
```

### config
Set the environment variable `LEMMY_DOMAIN` to run in single instance mode
```bash
docker run -it -e LEMMY_DOMAIN='lemmydomain.com' -p "8080:8080" ghcr.io/rystaf/mlmym:latest
```
