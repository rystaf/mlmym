.PHONY: dev reload serve VERSION

all: mlmym

mlmym:
	go build -v -o mlmym

dev:
	$(MAKE) -j2 --no-print-directory reload serve

reload:
	websocketd --loglevel=fatal --port=8009 watchexec --no-vcs-ignore -e html,css,js 'echo "$$WATCHEXEC_WRITTEN_PATH"'

VERSION:
	git describe --tag > $@

serve: VERSION
	DEBUG=true watchexec --no-vcs-ignore -e go -r "go run . --addr 0.0.0.0:8008 -w"
