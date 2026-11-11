# 需要 macOS + Xcode CLT；真机部署用 `codesign -s - --entitlements ent.plist`
CFLAGS  = -O2 -Wall -Wno-unused-variable
FRAMEWORKS = -framework IOKit -framework CoreFoundation -framework Foundation

all: iosurface_race ave_oob ane_oob spec_race

iosurface_race: iosurface_teardown_race.c
	clang $(CFLAGS) -o $@ $< $(FRAMEWORKS) -lpthread

ave_oob: ave_av1_oob.c
	clang $(CFLAGS) -o $@ $< $(FRAMEWORKS)

ane_oob: ane_procedure_oob.c
	clang $(CFLAGS) -o $@ $< $(FRAMEWORKS)

clean:
	rm -f iosurface_race ave_oob ane_oob spec_race

.PHONY: all clean

spec_race: spec_ioctl_revoke_race.c
	clang $(CFLAGS) -o $@ $< -lpthread
