.PHONY: check syntax lint selftest package clean

LUA ?= lua
LUAC ?= luac
LUACHECK ?= luacheck
TSHARK ?= tshark
VERSION ?= dev

check: syntax lint selftest

syntax:
	$(LUAC) -p plugin/dgproto.lua

lint:
	$(LUACHECK) --config .luacheckrc plugin/dgproto.lua

selftest:
	python scripts/validate.py --plugin plugin/dgproto.lua --tshark "$(TSHARK)"

package: check
	python scripts/package_release.py --version "$(VERSION)" --output-dir dist

clean:
	python -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('build', 'dist', '__pycache__')]"
