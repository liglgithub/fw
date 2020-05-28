libname:=libmnl libnfnetlink libnetfilter_queue libxml2 sqlite
installdir=$(dir $(shell pwd))
libdir=$(BUILDDIR)/lib/
incdir=$(BUILDDIR)/inc/

.PHONY: all clean

all:
	mkdir -p $(libdir) $(incdir)
	for i in ${libname}; do \
		if [[ "" != `find $(libdir) -maxdepth 1 -type l -name "*$${i}*\.so"` ]]; then \
			continue ; \
		fi; \
		echo "Compile $${i} ....";\
		tar -jxvf `find . -maxdepth 1 -type f -name "$${i}*\.tar\.bz2" -o -name "$${i}*\.tbz2"` >/dev/null 2>&1 || \
		tar -zxvf `find . -maxdepth 1 -type f -name "$${i}*\.tar\.gz" -o -name "$${i}*\.tgz"`  >/dev/null 2>&1 || \
		exit 1; \
		cd `find . -maxdepth 1 -type d -name "$${i}*"`; \
		export PKG_CONFIG_PATH=$(libdir)/pkgconfig ; ./configure --libdir=$(libdir) --includedir=$(incdir) || exit 2; \
		make install; \
		cd -; \
	done

clean:
	for i in ${libname}; do \
		rm -rf `find . -maxdepth 1 -type d -name "$${i}*"`; \
	done
