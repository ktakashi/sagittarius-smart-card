;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/commands.scm - Shell commands library
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

(library (pcsc shell commands)
    (export define-command
	    lookup-command
	    ;; utilities
	    aid->bytevector
	    retrieve-return-code
	    )
    (import (rnrs)
	    (prefix (pcsc control) pcsc:)
	    (sagittarius)
	    (sagittarius object)
	    (sagittarius control)
	    (tlv)
	    (srfi :39))

  (define *command-table* (make-eq-hashtable))
  (define *help-table* (make-eq-hashtable))

  (define (lookup-command command) (hashtable-ref *command-table* command #f))

  (define-syntax define-command
    (lambda (x)
      (syntax-case x (lambda)
	((_ (name . formals) help body ...)
	 #'(define-command name (lambda formals help body ...)))
	((_ name (lambda formals help body ...))
	 (string? (syntax->datum #'help))
	 #'(begin
	     (define name (lambda formals body ...))
	     (hashtable-set! *help-table* 'name help)
	     (hashtable-set! *command-table* 'name name)))
	((_ name (lambda formals body ...))
	 #'(begin
	     (define name (lambda formals body ...))
	     (hashtable-set! *command-table* 'name name))))))

  ;; predefined commands
  (define-command (help :optional (command #f))
    "help [command]\n\
     Show help message.\n\
     When [command] option is given, show the help of given command."
    (define (list-all-commands)
      (let1 keys (vector-map symbol->string (hashtable-keys *help-table*))
	(vector-sort! string<=? keys)
	(call-with-string-output-port
	 (lambda (out)
	   (display "\nFollowing commands are defined:\n" out)
	   (vector-for-each
	    (lambda (s) (display "    " out) (display s out) (newline out))
	    keys)))))
    (if command
	(hashtable-ref *help-table* command "no help available")
	(string-append (hashtable-ref *help-table* 'help "no help available")
		       (list-all-commands))))

  ;; useful commands
  (define *current-context* (make-parameter #f))
  (define-syntax check-context
    (syntax-rules ()
      ((_ who)
       (unless (*current-context*)
	 (assertion-violation 'who "context is not established")))))

  (define-command (establish-context :optional (scope pcsc:*scard-scope-user*))
    "establish-context [scope]\n\n\
     Establish card context. \n\
     If there is already a context, this it will release it before\n\
     establish one."
    (release-context)
    (*current-context* (pcsc:card-establish-context scope)))

  (define-command (release-context)
    "release-context\n\n\
     Release current card context"
    (when (*current-context*)
      (pcsc:card-release-context! (*current-context*))
      (*current-context* #f)))

  (define-command (card-readers)
    "card-readers\n\n\
     List all card readers."
    (check-context card-readers)
    (pcsc:card-list-readers (*current-context*)))

  (define *current-connection* (make-parameter #f))
  (define *current-protocol* (make-parameter #f))

  (define-command (card-connect reader :key (share pcsc:*scard-share-shared*)
				(protocol pcsc:*scard-protocol-any*))
    "card-connect reader :key share protocol\n\n\
     Connect to a card and returns actual protocol. \n\
     if there is already a connection, the it will be disconnected."
    (check-context card-connect)
    (card-disconnect)
    (receive (con ap) (pcsc:card-connect (*current-context*)
					 reader share protocol)
      (*current-connection* con)
      (*current-protocol* ap)
      ap))

  (define-command (card-disconnect :optional (how pcsc:*scard-leave-card*))
    "card-disconnect\n\n\
     Disconnect current connection."
    (when (*current-connection*) 
      (pcsc:card-disconnect! (*current-connection*) how)
      (*current-connection* #f)
      (*current-protocol* #f)))

  (define-syntax check-card
    (syntax-rules ()
      ((_ who)
       (unless (*current-connection*)
	 (assertion-violation 'who "card is not connected")))))

  (define-command (card-status)
    "card-status\n\n\
     Get card status from current connection."
    (check-card card-status)
    (pcsc:card-status (*current-connection*)))

  (define (retrieve-return-code response-apdu)
    (let1 len (bytevector-length response-apdu)
      (when (< len 2)
	(assertion-violation 'retrieve-return-code
			     "invalid response APDU" response-apdu))
      (bytevector-copy response-apdu (- len 2))))

  (define-command (send-apdu apdu)
    "send-apdu apdu\n\n\
     Sends given APDU to current connection and returns response."
    ;; assume current protocol is T0 or T1
    ;; TODO should I create a new card io request?
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
    (check-card send-apdu)
    (let* ((pci (if (= (*current-protocol*) pcsc:*scard-protocol-t1*)
		    pcsc:*scard-pci-t1*
		    pcsc:*scard-pci-t0*))
	   (buf (make-bytevector 256)))
      (receive (rl _) (pcsc:card-transmit! (*current-connection*)
					   pci 
					   (if (bytevector? apdu)
					       apdu
					       (parse-apdu apdu)) 
					   buf)
	(if (= rl (bytevector-length buf))
	    buf
	    (bytevector-copy buf 0 rl)))))

  (define (aid->bytevector aid)
    (cond ((symbol? aid)
	   (integer->bytevector (string->number (symbol->string aid) 16)))
	  ((number? aid)
	   ;; assume it doesn't start with #x00
	   ;; and most likely hex without alphabet
	   (integer->bytevector (string->number (format "~a" aid) 16)))
	  ((bytevector? aid) aid)
	  (else
	   (assertion-violation 'aid->bytevector
				"invalid aid type to handle" aid))))

  (define-command (select :key (aid #f))
    "select :key aid\n\n\
     Sends select command."
    ;; cla and ins
    (define base-command #vu8(#x00 #xA4 #x04 #x00))
    (send-apdu
     (call-with-bytevector-output-port
      (lambda (out)
	(put-bytevector out base-command)
	(if aid
	    (let1 bv (aid->bytevector aid)
	      (put-u8 out (bytevector-length bv))
	      (put-bytevector out bv))
	    (put-u8 out 0))))))

  (define-command (get-status type :key (aid #f) (contactless #f))
    "get-status types :key aid\n\n\
     Transmit GET STATUS command.\n  \
     * type: status type must be issuer, applications, loadfiles or modules"
    (let ((p1 (case type
		((issuer)       #x80)
		((applications) #x40)
		((loadfiles)    #x20)
		((modules)      #x10)
		(else (assertion-violation 
		       'get-status
		       "type must issuer, applications, loadfile or modules"
		       type))))
	  (p2 (if contactless #x00 #x02)))
      (define (construct-apdu p2)
	(call-with-bytevector-output-port
	 (lambda (out)
	   (put-u8 out #x80) (put-u8 out #xF2)
	   (put-u8 out p1)   (put-u8 out p2)
	   (if aid
	       (let1 bv (aid->bytevector aid)
		 (put-u8 out (+ (bytevector-length bv) 1))
		 (put-u8 out #x4F)
		 (put-bytevector bv))
	       (begin (put-u8 out 2) (put-u8 out #x4F) (put-u8 out #x00))))))
      (call-with-bytevector-output-port
       (lambda (out)
	 (let loop ((response (send-apdu (construct-apdu p2))))
	   (cond ((bytevector=? #vu8(#x63 #x10)
				(retrieve-return-code response))
		  (put-bytevector out response 
				  0 (- (bytevector-length response) 2))
		  (loop (send-apdu (construct-apdu (bitwise-ior #x0001 p2)))))
		 (else (put-bytevector out response))))))))

  (define-command (trace-on)
    "trace-on\n\n\
     Enable trace log."
    (pcsc:*trace-on* #t))

  (define-command (trace-off)
    "trace-off\n\n\
     Disable trace log."
    (pcsc:*trace-on* #f))

)