INCLUDES  = -I ../build/inc -I ../build/inc/libxml2
LDFLAGS   = -L ../build/lib -lnfnetlink -lnetfilter_queue -pthread -ldl -lsqlite3 -lxml2
CFLAGS    = -Wall -Wextra -Werror -O3
CC	  = gcc
RPATH	  = -Wl,-rpath,'$$ORIGIN/../lib:./'
BUILDDIR  = `dirname $(shell pwd)`/build
DESTDIR   = $(BUILDDIR)

ifdef DEBUG
	CFLAGS += -DDEBUG -g
endif

.PHONY:all clean
all:fw fwcmd fwcli

fw:	main.c \
	fwinit.c \
	fwcb.c \
	fwserv.c \
	fwdb.c \
	fwlog.c \
	fwparse.c \
	fwutil.c \
	fwrule.c \
	fwlogger.c \
	zf_log.c
	export BUILDDIR=$(BUILDDIR);make -C ../third-party
	$(CC) $(CFLAGS) $^ -o $@ $(RPATH) $(INCLUDES) $(LDFLAGS) 

fwcmd:fwcmd.c fwdb.c fwutil.c zf_log.c
	$(CC) $(CFLAGS) $^ -o $@  $(RPATH) $(INCLUDES) -L ../build/lib/ -pthread -ldl -lsqlite3

fwcli:fwcli.c fwutil.c
	$(CC) $(CFLAGS) $^ -o $@ 

install:fw fwcmd fwcli
	@mkdir -p $(DESTDIR)
ifneq ($(BUILDDIR),$(DESTDIR))
	@cp -ar $(BUILDDIR)/* $(DESTDIR)
endif
	@mkdir -p $(DESTDIR)/log
	@mkdir -p $(DESTDIR)/etc
	@mkdir -p $(DESTDIR)/db 
	@mkdir -p $(DESTDIR)/bin
	@mv -f fw    $(DESTDIR)/bin/
	@mv -f fwcmd $(DESTDIR)/bin/
	@mv -f fwcli $(DESTDIR)/bin/
	@cp -f iprule.xml $(DESTDIR)/etc/
	@echo install ok

clean:
	-rm -fr ../build/ fw fwcmd fwcli
	make clean -C ../third-party
