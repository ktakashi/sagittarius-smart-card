;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/shell/repl.scm - interactive envirionment for PCSC
;;;  
;;;   Copyright (c) 2013  Takashi Kato  <ktakashi@ymail.com>
;;;   
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;   
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;  
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;  
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;  
(library (pcsc shell repl)
    (export pcsc-load pcsc-repl pcsc-eval
	    pcsc-repl-evaluator
	    pcsc-repl-promptor
	    pcsc-repl-exception-printer
	    pcsc-repl-printer
	    pcsc-repl-reader
	    *verbose*)
    (import (rnrs)
	    (rnrs eval)
	    (util file)
	    (sagittarius)
	    (sagittarius control)
	    (pcsc operations)
	    (pcsc shell commands)
	    (srfi :39))

  (define (pcsc-eval expr)
    (define (convert v)
      (if (bytevector? v)
	  (bytevector->hex-string v)
	  v))
    (let* ((name (if (pair? expr) (car expr) expr))
	   (handler (lookup-command name)))
      (cond (handler
	     (if (pair? expr)
		 ;; get evaluated arguments
		 (receive r (apply handler (map pcsc-eval (cdr expr)))
		   ;; bytevectors are most likely APDU from command
		   (let1 converted (map convert r)
		     (apply values converted)))
		 (pcsc-eval `(help ',name))))
	    (else (eval expr (current-library))))))

  (define *verbose* (make-parameter #f))

  (define (pcsc-load file)
    (let loop ((commands (file->sexp-list file)) (r '()))
      (if (null? commands)
	  (apply values r)
	  (receive rs (pcsc-eval (car commands))
	    (when (*verbose*)
	      (format (current-output-port) "~s~%" (car commands))
	      (for-each (lambda (r) (format/ss (current-output-port)
					       " --> ~s~%" r))  rs))
	    (loop (cdr commands) rs)))))

  (define-command (exit)
    "exit\n\nquit REPL"
    ;; we don't know if it's release before exit, so just in case.
    ((lookup-command 'release-context))
    (quit? #t))

  (define-command (load-script file :optional (verbose #f))
    "load-script file [verbose]\n\n\
     Loads PCSC script that this library can evaluate."
    (parameterize ((*verbose* verbose)) (pcsc-load file)))

  (define quit? (make-parameter #f))

  (define (default-printer . args)
    (for-each (lambda (arg) (format/ss (current-output-port) "~a~%" arg)) args))
  (define (default-reader in) (read/ss in))
  (define (default-prompter) (display "pcsc> "))
  (define (default-exc-printer c) (report-error c))

  (define-syntax define-repl-parameter
    (syntax-rules ()
      ((_ name value)
       (define name (make-parameter 
		     value 
		     (lambda (x)
		       (cond ((not x) values)
			     ((procedure? x) x)
			     (else
			      (assertion-violation 
			       'name
			       (format "expected procedure or #f, but got ~s"
				       x))))))))))

  (define-repl-parameter pcsc-repl-printer default-printer)
  (define-repl-parameter pcsc-repl-reader default-reader)
  (define-repl-parameter pcsc-repl-promptor default-prompter)
  (define-repl-parameter pcsc-repl-exception-printer default-exc-printer)
  (define-repl-parameter pcsc-repl-evaluator pcsc-eval)

  (define (pcsc-repl)
    (quit? #f)
    (let loop ()
      (call/cc
       (lambda (continue)
	 (with-error-handler
	   (lambda (c)
	     (flush-output-port)
	     ((pcsc-repl-exception-printer) c)
	     (and (serious-condition? c) (continue)))
	   (lambda ()
	     ((pcsc-repl-promptor))
	     (flush-output-port)
	     (let ((expr ((pcsc-repl-reader) (current-input-port))))
	       (and (eof-object? expr) (set! expr '(exit)))
	       (receive ans ((pcsc-repl-evaluator) expr)
		 (apply (pcsc-repl-printer) ans)
		 (flush-output-port)))))))
      (unless (quit?) (loop))))
)
