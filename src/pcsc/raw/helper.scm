;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/raw/helper.scm - helper library.
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
#!read-macro=sagittarius/regex
(library (pcsc raw helper)
    (export define-c-function)
    (import (rnrs)
	    (sagittarius)
	    (sagittarius ffi)
	    (sagittarius control)
	    (sagittarius regex))

  (define win-scard-library (open-shared-library (include "dll.incl")))

  (define-syntax define-c-function
    (lambda (x)
      (define (scheme-name->c-name name suffix)
	(let1 items (string-split (symbol->string name) #/-/)
	  (string->symbol
	   (let1 base-name 
	       (string-concatenate (map (^s (string-titlecase s)) items))
	     (if (or (zero? (string-length suffix))
		     (cond-expand ((or windows cygwin) #f)
				  (else #t)))
		 base-name
		 (string-append base-name suffix))))))
      (syntax-case x ()
	((_ ret-value name arguments ...)
	 (symbol? (syntax->datum #'ret-value))
	 #'(define-c-function "" ret-value name arguments ...))
	((_ suffix ret-value name arguments ...)
	 (and (symbol? (syntax->datum #'name))
	      (symbol? (syntax->datum #'ret-value))
	      (string? (syntax->datum #'suffix)))
	 (with-syntax ((c-name (scheme-name->c-name (syntax->datum #'name)
						    (syntax->datum #'suffix))))
	   #'(define name (c-function win-scard-library ret-value c-name
				      (arguments ...))))))))

  )