CC = gcc
SUBMODULES = gui/console gui/gtk module

all: buildsubmodules

buildsubmodules:
	for n in $(SUBMODULES); do $(MAKE) -C $$n || exit 1; done

clean:
	for n in $(SUBMODULES); do $(MAKE) -C $$n clean; done
