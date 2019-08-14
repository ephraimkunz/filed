CC = gcc
CFLAGS = -I. -std=gnu11 -Wall -Werror -Wextra -W -pthread -D_FILE_OFFSET_BITS=64 $(FILED_EXTRA_CFLAGS)
LDFLAGS = -pthread $(FILED_EXTRA_LDFLAGS)
LIBS = -lpthread $(FILED_EXTRA_LIBS)
MIMETYPES = /etc/httpd/mime.types

PREFIX = /usr/local
prefix = $(PREFIX)
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
srcdir = .
vpath %.c $(srcdir)

all: release

release: CFLAGS += -O3 -DNDEBUG
release: filed.o filed_main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

debug: CFLAGS += -DDEBUG -g3
debug: filed.o filed_main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

test: CFLAGS += -DDEBUG -g3
test: filed_test.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" $^ $(LIBS)

filed.o: $(srcdir)/filed.c filed-mime-types.h 

filed_main.o: $(srcdir)/filed_main.c filed.h

filed_test.o: $(srcdir)/filed_test.c

filed-mime-types.h: $(srcdir)/generate-mime-types $(srcdir)/mime.types
	'$(srcdir)/generate-mime-types' '$(MIMETYPES)' > filed-mime-types.h.new || \
		'$(srcdir)/generate-mime-types' '$(srcdir)/mime.types' > filed-mime-types.h.new
	mv filed-mime-types.h.new filed-mime-types.h

install: filed $(srcdir)/filed.1
	test -d "$(DESTDIR)$(mandir)/man1" || mkdir -p "$(DESTDIR)$(mandir)/man1"
	test -d "$(DESTDIR)$(bindir)" || mkdir -p "$(DESTDIR)$(bindir)"
	cp '$(srcdir)/filed.1' "$(DESTDIR)$(mandir)/man1/"
	cp filed "$(DESTDIR)$(bindir)/"

clean:
	rm -f filed.o filed_main.o filed_test.o
	rm -f filed-mime-types.h.new
	rm -f debug release test

distclean: clean
	rm -f filed-mime-types.h

.PHONY: all install clean distclean
