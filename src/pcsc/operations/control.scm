;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/operations/control.scm - higher APIs for PC/SC library.
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
(library (pcsc operations control)
    (export *scard-scope-user* *scard-scope-terminal* *scard-scope-system*

	    *scard-share-shared* *scard-share-exclusive* *scard-share-direct*

	    *scard-protocol-t0* *scard-protocol-t1* *scard-protocol-raw*
	    *scard-protocol-t15* *scard-protocol-any* *scard-protocol-undefined*

	    *scard-leave-card* *scard-reset-card* *scard-unpower-card*
	    *scard-eject-card*

	    *scard-pci-t0* *scard-pci-t1* *scard-pci-raw*
	    ;; wrapper procedures
	    card-establish-context card-release-context!
	    card-list-readers card-list-reader-groups
	    card-connect card-disconnect! card-reconnect
	    card-status
	    card-transmit
	    card-transmit!
	    ;; utility
	    call-with-card-context
	    bytevector->hex-string
	    ;; for debugging
	    *trace-on*
	    
	    ;; condition
	    &pcsc-error pcsc-error? condition-return-code
	    )
    (import (rnrs)
	    (sagittarius)
	    (sagittarius control)
	    (sagittarius ffi)
	    (sagittarius regex)
	    (srfi :39)
	    (pcsc raw))

  (define *trace-on* (make-parameter #f))

  (define-syntax trace-log
    (syntax-rules ()
      ((_ expr ...)
       (when (*trace-on*)
	 (for-each (lambda (exp) (display exp (current-error-port)))
		   (list expr ...))
	 (newline (current-error-port))))))

  (define-condition-type &pcsc-error &error
    make-pcsc-error pcsc-error?
    (return-code condition-return-code))

  (define (bytevector->hex-string bv :optional (len (bytevector-length bv)))
    (call-with-string-output-port
     (lambda (out)
       (do ((i 0 (+ i 1)))
	   ((= i len))
	 (format out "~2,'0X" (bytevector-u8-ref bv i))))))

  (define translate-error-code error-code->string)

  (define (raise-pcrc-error who msg retcode . irr)
    (raise (apply condition
		  (filter values
			  (list (make-pcsc-error retcode)
				(and who (make-who-condition who))
				(make-message-condition 
				 (format "~a [~a]" msg
					 (translate-error-code retcode)))
				(make-irritants-condition irr))))))

  (define NULL null-pointer)

  (define-syntax check-error
    (syntax-rules ()
      ((_ rv who msg irr ...)
       (unless (= *scard-s-success* rv)
	 (raise-pcrc-error 'who msg rv irr ...)))))

  (define (card-establish-context scope)
    (let* ((hSC (empty-pointer))
	   (r (s-card-establish-context scope NULL NULL (address hSC))))
      (check-error r card-establish-context "failed to establish card context")
      hSC))

  (define (card-release-context! context)
    (let1 r (s-card-release-context context)
      (check-error r card-release-context! "failed to release card context")
      #t))

  (define (call-with-card-context proc :key (scope *scard-scope-user*))
    (let1 hSC (card-establish-context scope)
      (unwind-protect (proc hSC) (card-release-context! hSC))))

  (define (split-null-sep-string p size)
    (let1 items (string-split
		 (utf8->string (pointer->bytevector p size)) #/\x00/)
      (filter values (map (^s (if (zero? (string-length s)) #f s)) items))))

  (define (card-list-readers context :optional (groups ""))
    (define no-result-codes (list *scard-e-reader-unavailable*
				  *scard-e-no-readers-available*))
    (let* ((buffer (empty-pointer))
	   (cch     (integer->pointer *scard-autoallocate*))
	   (r (s-card-list-readers context groups
				   (address buffer) (address cch))))
      (cond ((memv r no-result-codes) '())
	    (else
	     (check-error r card-readers "failed to read card reader list")
	     (let1 readers (split-null-sep-string buffer (pointer->integer cch))
	       (s-card-free-memory context buffer)
	       readers)))))

  (define (card-list-reader-groups context :optional (groups ""))
    (let* ((buffer (empty-pointer))
	   (cch    (integer->pointer *scard-autoallocate*))
	   (r (s-card-list-reader-groups context 
					 (address buffer) (address cch))))
      (check-error r card-reader-groups "failed to read card reader group list")
      (let1 groups (split-null-sep-string buffer (pointer->integer cch))
	(s-card-free-memory context buffer)
	groups)))

  ;; reader = #f means auto detection
  (define (card-connect context reader mode protocol)
    (define (connect reader :optional (auto-detect? #f))
      (let* ((card (empty-pointer))
	     (ap   (empty-pointer))
	     (r    (s-card-connect context reader mode protocol
				   (address card) (address ap))))
	(if (and auto-detect? (= r *scard-w-removed-card*))
	    (values #f #f)
	    (begin
	      (check-error r card-connect "failed to connect a card")
	      (let1 ap (pointer->integer ap)
		(trace-log "Card connection protocol: " ap)
		(values card ap))))))
    (if reader
	(connect reader)
	(let loop ((readers (card-list-readers context)))
	  (if (null? readers)
	      (raise-pcrc-error 'card-connect "can't find any reader")
	      (receive (card ap) (connect (car readers) #t)
		(if card
		    (values card ap)
		    (loop (cdr readers))))))))

  (define (card-disconnect! card disposition)
    (let1 r (s-card-disconnect card disposition)
      (check-error r card-disconnect! "failed to disconnect the card")
      #t))

  (define (card-status card)
    (let* ((reader (empty-pointer))
	   (cch    (integer->pointer *scard-autoallocate*))
	   (state  (empty-pointer))
	   (protocol (empty-pointer))
	   (atr    (empty-pointer))
	   (cb     (integer->pointer *scard-autoallocate*))
	   (r (s-card-status card
			     (address reader) (address cch)
			     (address state)
			     (address protocol)
			     (address atr) (address cb))))
      (check-error r card-status "failed to get status")
      (let ((bv (pointer->bytevector atr (pointer->integer cb)))
	    (readers (split-null-sep-string reader (pointer->integer cch))))
	(values readers (pointer->integer state)
		(pointer->integer protocol) bv))))

  (define (card-transmit card protocol send-data
			 :optional (need-pci #f))
    (let1 buffer (make-bytevector 256)
      (receive (rl pci) (card-transmit! card protocol send-data buffer need-pci)
	(if (= rl (bytevector-length buffer))
	    (values buffer pci)
	    (values (bytevector-copy buffer 0 rl) pci)))))

  (define (card-transmit! card protocol send-data recv-buffer
			  :optional (need-pci #f))
    (define (transmit&response apdu recv-pci)
      (define (transmit apdu recv-pci recv-length)
	(s-card-transmit card protocol
			 apdu (bytevector-length apdu)
			 recv-pci
			 recv-buffer (address recv-length)))
      (let* ((r-l (integer->pointer (bytevector-length recv-buffer)))
	     (r (transmit apdu recv-pci r-l)))
	(if (= (bytevector-u8-ref recv-buffer 0) #x61)
	    ;; get responce
	    (let* ((len (bytevector-u8-ref recv-buffer 1))
		   (cmd (bytevector-copy #vu8(#x00 #xC0 #x00 #x00 0)))
		   (r-l (integer->pointer (bytevector-length recv-buffer))))
	      ;; reset buffer
	      (bytevector-fill! recv-buffer 0)
	      (bytevector-u8-set! cmd 4 len)
	      (let1 r (transmit cmd recv-pci r-l)
		(values r (pointer->integer r-l))))
	    (values r (pointer->integer r-l)))))

    (trace-log "Transmitting APDU")
    (trace-log " S: " (bytevector->hex-string send-data))
    (let1 recv-pci (if need-pci (create-pci 0) NULL)
      (receive (r buffer-length) (transmit&response send-data recv-pci)
	(check-error r card-transmit! "failed to transmit given data"
		     send-data)
	(trace-log " R: " (bytevector->hex-string recv-buffer buffer-length))
	(values buffer-length (and need-pci recv-pci)))))

  )