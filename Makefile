.PHONY: dev reload serve VERSION

all: mlmym

mlmym:
	go build -v -o mlmym

dev:
	$(MAKE) -j2 --no-print-directory reload serve

reload:
	websocketd --loglevel=fatal --port=8009 watchexec -e html,css,js -d 500 'echo "$$WATCHEXEC_WRITTEN_PATH"'

VERSION:
	git describe --tag > $@

serve: VERSION
	DEBUG=true watchexec --no-vcs-ignore -e go -r "go run . --addr 0.0.0.0:8008 -w"
