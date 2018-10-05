Styled Fileserver
=================

This fileserver is a very minor change ontop of the built in golang
fileserver.  It adds a few things:

1. Fitler out .dotfiles
2. Use lets encrypt
3. Use a basic template for layout
  - This lets me add id values to the links generated so I can know if something is
    a `.filelink` or `.folderlink` w/o too much processing post fact

What you need to compile:

[golang v1.11+](https://golang.org/dl/)
[packr](https://github.com/gobuffalo/packr)

sass compiler of some sort
gnu Make

Compile
=======

```
make
```

Usage
=====

Prod
----
run `./fileserver -serveDir <directory you want to share> -domains <coma.net,separated.org,domain.co,list.com>`

This will do HTTP/2 TLS only serving (probably does http/1.1 as well, but didn't bother to check).  You need to be listening
on the domain you specified.  This will fetch you a *letsencrypt* certificate for the domain/domains listed.  Should do the
refreshing as well: but haven't checked

https://godoc.org/golang.org/x/crypto/acme/autocert#NewListener


Testing
-------

don't do this excecpt for testing

run `./fileserver -serveDir <directory you want to share> -tls false
