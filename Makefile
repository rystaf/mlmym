.PHONY: dev reload serve style

all: 
	$(MAKE) -j3 --no-print-directory dev

dev: reload serve style

reload:
	#websocketd --port=8080 watchexec -w public echo reload &>/dev/null
	websocketd --loglevel=fatal --port=8009 watchexec --no-vcs-ignore -e html,css,js -d 500 -w public 'echo "$$WATCHEXEC_WRITTEN_PATH"'

serve:
	#python  -m http.server --directory ./public 8081 &>/dev/null
	watchexec -e go -r "go run . --addr 0.0.0.0:8008 -w"

style:
	npm run watchcss > /dev/null 2>&1
