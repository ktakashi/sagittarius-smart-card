(import (pcsc shell)
	(getopt))

(define (main args)
  (define (usage args)
    (print (car args) ": -f $file")
    (exit #f))
  (with-args args ((file (#\f "file") #t (usage args)))
    (pcsc-load file)))