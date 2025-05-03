# mlmym
a familiar desktop experience for [lemmy](https://join-lemmy.org).

![screenshot](https://raw.githubusercontent.com/rystaf/mlmym/main/screenshot1.png?raw=true)

## deployment

```bash
docker run -it -p "8080:8080" ghcr.io/rystaf/mlmym:latest
```

## config
Set the environment variable `LEMMY_DOMAIN` to run in single instance mode
```bash
docker run -it -e LEMMY_DOMAIN='lemmydomain.com' -p "8080:8080" ghcr.io/rystaf/mlmym:latest
```
#### default user settings
| environment variable   | default |
|------------------------| ------- |
| LISTING                | All |
| SORT                   | Hot |
| COMMENT_SORT           | Hot |
| DARK                   | false |
| HIDE_THUMBNAILS        | false |
| COLLAPSE_MEDIA         | false |
| LINKS_IN_NEW_WINDOW    | false |
| COMMENTS_IN_NEW_WINDOW | false |

To override a default setting to true, set the environment variable to any value. To undo an override, leave the variable blank.
