;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/operations/program.scm - high APIs for PC/SC library.
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

;; bad name for the library but no choice... orz
(library (pcsc operations program)
    (export &channel channel-error
	    call-with-card-connection
	    select-application
	    delete-application
	    get-status
	    set-status
	    open-secure-channel
	    call-with-secure-channel
	    send-apdu
	    aid->bytevector

	    ;; constants
	    +issuer+
	    +application+
	    +loadfile+
	    +module+
	    )
    (import (rnrs)
	    (sagittarius)
	    (sagittarius control)
	    (sagittarius object)
	    (srfi :13 strings)
	    (tlv)
	    (pcsc operations gp)
	    (pcsc operations apdu)
	    (pcsc operations control))

  (define-condition-type &chennel &pcsc-error
    make-channel-error chennel-error?)

  (define (channel-error who msg retcode . irr)
    (raise (apply condition
		  (filter values
			  (list (make-channel-error retcode)
				(and who (make-who-condition who))
				(make-message-condition msg)
				(make-irritants-condition irr))))))


  (define (send-apdu conn apdu :optional (sc-context #f))
    (define (parse-apdu apdu)
      (let* ((s (if (number? apdu)
		    (number->string apdu 16)
		    (->string apdu)))
	     (len (/ (string-length s) 2)))
	(unless (integer? len)
	  (assertion-violation 'send-apdu "invalid APDU" s))
	(do ((i 0 (+ i 1)) (bv (make-bytevector len)))
	    ((= i len) bv)
	  (let1 u8 (substring s (* i 2) (+ (* i 2) 2))
	    (bytevector-u8-set! bv i (string->number u8 16))))))
    (let ((apdu (if (bytevector? apdu) apdu (parse-apdu apdu))))
      (let-values (((resp _) (card-transmit conn 
					    (encode-apdu sc-context apdu))))
	resp)))


  ;; bit more programatical APIs
  ;; I think most of the case once card context is initialised
  ;; then it won't be released until the script it done and it's
  ;; when .dll is release it will be released (I hope). so keep
  ;; the context in parameter (or even global variable), and
  ;; do not show it to users.
  (define (call-with-card-connection proc :key (reader #f)
				     (share *scard-share-shared*)
				     (protocol *scard-protocol-any*)
				     (scope *scard-scope-user*))
    ;; in case :)
    (let1 context (card-establish-context scope)
      (let-values (((conn ap) (card-connect context reader share protocol)))
	(unwind-protect
	    (proc conn)
	  (card-disconnect! conn *scard-reset-card*)))))


  (define (open-secure-channel conn enc-key mac-key dek-key
			       :key (key-id 0) (key-version 0)
			       ;; default mac at least ...
			       (security-level *security-level-mac*)
			       (derive-key derive-key-none)
			       ;; what is this exactly?
			       (option #x55)
			       (raise #t))
    (let1 protocol (and (not option) (make-bytevector 255))
      (unless option
	;; tag 66
	(let1 data (bytevector->hex-string 
		    (send-apdu conn #vu8(#x80 #xCA #x00 #x66 #x00)))
	  (do ((offset 0 (+ index 18))
	       (index (string-contains-ci data "2A864886FC6B04" 0)
		      (string-contains-ci data "2A864886FC6B04" index)))
	      ((not index))
	    (let ((scp (->integer (substring data (+ index 14) (index 16)) 16))
		  (v   (->integer (substring data (+ index 16) (index 18)) 16)))
	      (bytevector-u8-set! protocol scp index)))))
      (let* ((context (make-secure-channel-context key-version key-id
						   :option option))
	     (rsp (send-apdu conn (initialize-update context))))
	(when (and (not option) (> (bytevector-length rsp) 12))
	  (let* ((scp (bitwise-and (bytevector-u8-ref rsp 11) #xFF))
		 (v   (bytevector-u8-ref protocol scp)))
	    (when (positive? v) (sc-context-option-set! context v))))
	(let1 authenticated? (authenticate-card context rsp
						enc-key mac-key dek-key 
						derive-key)
	  (cond (authenticated?
		 (let1 result (send-apdu conn (external-authenticate 
					       context security-level))
		   (values context result)))
		(raise
		 (channel-error 'channel
		  "card could not be authenicated with the supplied keys!"
		  "Authentication failed"))
		(else (values #f #f)))))))

  (define (call-with-secure-channel conn enc-key mac-key dek-key
				    proc . options)
    (let-values (((context result)
		  (apply open-secure-channel conn enc-key mac-key dek-key
			 options)))
      ;; should we invalidate the context?
      (proc context result)))

  ;; utility
  (define (aid->bytevector aid)
    (cond ((symbol? aid)
	   (integer->bytevector (string->number (symbol->string aid) 16)))
	  ((number? aid)
	   ;; assume it doesn't start with #x00
	   ;; and most likely hex without alphabet
	   (integer->bytevector aid))
	  ((bytevector? aid) aid)
	  (else
	   (assertion-violation 'aid->bytevector
				"invalid aid type to handle" aid))))

  (define (select-application conn :key (aid #vu8()))
    (send-apdu conn (compose-apdu #x00 #xA4 #x04 #x00 aid)))

  (define (tlv*->bytevector tlv*)
    (bytevector-concatenate (map tlv->bytevector tlv*)))

  (define (delete-application conn aid :key (cascade #f) (token #f)
			      (sc-context #f))
    (let ((p2 (if cascade #x80 #x00))
	  (lc&tag (make-bytevector 2 #x4F)))
      (send-apdu conn 
		 (compose-apdu 
		  #x80 #xE4 #x00 p2
		  (tlv*->bytevector
		   (->tlv `((#x4F . ,aid)
			    . ,(if token
				   `((#9F . ,token))
				   '())))))
		 sc-context)))

  (define-constant +issuer+      #x80)
  (define-constant +application+ #x40)
  (define-constant +loadfile+    #x20)
  (define-constant +module+      #x10)

  (define (get-status conn type :key (aid #f) (contactless #f)
		      (sc-context #f))
    (let ((p1 type)
	  (p2 (if contactless #x00 #x02)))
      (define (construct-apdu p2)
	(compose-apdu 
	 #x80 #xF2 p1 p2 
	 (tlv*->bytevector
	  (->tlv `((#x4F . ,(if aid aid '())))))))
      (call-with-bytevector-output-port
       (lambda (out)
	 (let loop ((response (send-apdu conn (construct-apdu p2)
					 sc-context)))
	   (cond ((response-code=? response #x6310)
		  (put-bytevector out response
				  0 (- (bytevector-length response) 2))
		  (loop (send-apdu conn (construct-apdu (bitwise-ior #x0001 p2))
				   sc-context)))
		 (else (put-bytevector out response))))))))

  (define (set-status conn type control :key (aid #vu8()) (sc-context #f))
    (send-apdu conn (compose-apdu #x80 #xF0 type control aid)
	       sc-context))

)