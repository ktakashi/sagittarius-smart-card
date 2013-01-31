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
	    invoke-command
	    ;; utilities
	    aid->bytevector
	    retrieve-return-code
	    (rename (gp:*security-level-none* *security-level-none*)
		    (gp:*security-level-mac*  *security-level-mac*)
		    (gp:*security-level-enc*  *security-level-enc*)
		    (gp:*security-level-renc* *security-level-renc*))
	    ;; variables
	    ;; get-status
	    issuer applications loadfiles modules
	    ;; get-data
	    iin
	    card-image-number
	    card-data
	    key-information-template
	    extended-card-recources
	    cplc)
    (import (rnrs)
	    (prefix (pcsc operations control) pcsc:)
	    (prefix (pcsc operations gp) gp:)
	    (sagittarius)
	    (sagittarius object)
	    (sagittarius control)
	    (util file)
	    (tlv)
	    (srfi :13)
	    (srfi :39))

  (define *command-table* (make-eq-hashtable))
  (define *help-table* (make-eq-hashtable))

  (define (lookup-command command) (hashtable-ref *command-table* command #f))

  (define-syntax invoke-command
    (syntax-rules ()
      ((_ command args ...)
       ((lookup-command 'command) args ...))))

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
    ;; just in case
    (card-disconnect pcsc:*scard-reset-card*)
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

  (define-command (card-connect :optional (reader #f)
				:key (share pcsc:*scard-share-shared*)
				(protocol pcsc:*scard-protocol-any*))
    "card-connect [reader] :key share protocol\n\n\
     Connect to a card and returns actual protocol. \n\
     if there is already a connection, the it will be disconnected."
    (check-context card-connect)
    (card-disconnect pcsc:*scard-reset-card*)
    (receive (con ap) (pcsc:card-connect (*current-context*)
					 reader share protocol)
      (*current-connection* con)
      (*current-protocol* ap)
      ap))

  (define-command (card-disconnect :optional (how pcsc:*scard-leave-card*))
    "card-disconnect\n\n\
     Disconnect current connection."
    (when (*current-connection*)
      (close-channel)
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

  (define *current-sc* (make-parameter #f))

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
    (let ((pci (if (= (*current-protocol*) pcsc:*scard-protocol-t1*)
		   pcsc:*scard-pci-t1*
		   pcsc:*scard-pci-t0*))
	  (apdu (if (bytevector? apdu) apdu (parse-apdu apdu))))
      (receive (resp _)
	  (pcsc:card-transmit (*current-connection*)
			      pci (gp:encode-apdu (*current-sc*) apdu))
	resp)))

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

  (define-constant issuer       #x80)
  (define-constant applications #x40)
  (define-constant loadfiles    #x20)
  (define-constant modules      #x10)

  (define-command (get-status type :key (aid #f) (contactless #f))
    "get-status types :key aid\n\n\
     Transmit GET STATUS command.\n  \
     * type: status type must be issuer, applications, loadfiles or modules"
    (let ((p1 type)
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
	   (cond ((gp:response-code=? response #x6310)
		  (put-bytevector out response
				  0 (- (bytevector-length response) 2))
		  (loop (send-apdu (construct-apdu (bitwise-ior #x0001 p2)))))
		 (else (put-bytevector out response))))))))

  ;; issuer identification number
  (define-constant iin                      #x0042)
  (define-constant card-image-number        #x0045)
  (define-constant card-data                #x0066)
  (define-constant key-information-template #x00E0)
  (define-constant extended-card-recources  #xFF21)
  (define-constant cplc                     #x9F7F)

  (define-command (get-data record)
    "get-data record\n\n\
     Transmit GET DATA command.\n  \
     * record: P1 and P2 values (exact integer)."
    (send-apdu (bytevector-append #vu8(#x80 #xCA)
				  (integer->bytevector record 2)
				  #vu8(#x00))))

  (define-command (trace-on)
    "trace-on\n\n\
     Enable trace log."
    (pcsc:*trace-on* #t))

  (define-command (trace-off)
    "trace-off\n\n\
     Disable trace log."
    (pcsc:*trace-on* #f))

  ;; open secure channel
  (define *enc-key* (make-parameter #f))
  (define *mac-key* (make-parameter #f))
  (define *dek-key* (make-parameter #f))

  (define-command (set-keys! :key (enc #f) (mac #f) (dek #f))
    "set-keys! :key enc mac dek\n\n\
     Sets default keys. If #f is given it won't do anything. non bytevector value sets #f as default key (reset)"
    (define (set-key! p v)
      (when v
	(if (bytevector? v)
	    (p v)
	    (p #f))))
    (set-key! *enc-key* enc)
    (set-key! *mac-key* mac)
    (set-key! *dek-key* dek))

  (define-condition-type &chennel pcsc:&pcsc-error
    make-channel-error chennel-error?)
  (define (raise-channel-error who msg retcode . irr)
    (raise (apply condition
		  (filter values
			  (list (make-channel-error retcode)
				(and who (make-who-condition who))
				(make-message-condition msg)
				(make-irritants-condition irr))))))

  (define *master-keys* (make-parameter #f))
  (define-command (load-key-list file)
    "load-key-list file\n\n\
     Convenient command. Loads key lists from given file and 'channel' command \
     tries to search proper key from the list.\n\
     The file format must be like this;\n\
     $key = bv, string, or integer\n\
     ($key)\n\
     ($key $key $key)\n\
     The first form uses given key for all keys. The second form then\
     $keys are ENC, MAC, DEK respectively."
    (*master-keys* (file->sexp-list file)))

  (define-command (set-key-list! lst)
    "set-key-list! list\n\n\
     Convenient command. Similar with load-key-list but this one sets the give \
     list to search list."
    (*master-keys* lst))

  (define-command (channel :key (security gp:*security-level-none*)
			   (key-id 0) (key-version 0)
			   (option #f)
			   ;; keys
			   (enc-key (*enc-key*))
			   (mac-key (*mac-key*))
			   (dek-key (*dek-key*))
			   (derive-key gp:derive-key-none))
    "channel :key security key-id key-version enc-key mac-key dek-key\n\n\
     Opens secure channel with given parameters. Keyword arguments specify\
     Following parameters:\n  \
     * security: specify security level must be *security-level-none*,\n    \
       *security-level-mac*, *security-level-enc* or *security-level-renc*.\n  \
     * options:  implementation option. must be fixnum.\n  \
     * key-id:   key identifier.\n  \
     * key-version: key version.\n  \
     * enc-key, mac-key, dec-key: keys to authenticate. if these are not \n    \
       specified *enc-key*, *mac-key* or *dek-key* parameters will be used."
    ;; closes current channel if there is.
    (close-channel)
    (let1 protocol (and (not option) (make-bytevector 255))
      (unless option
	;; tag 66
	(let1 data (pcsc:bytevector->hex-string
		    (send-apdu #vu8(#x80 #xCA #x00 #x66 #x00)))
	  (do ((offset 0 (+ index 18))
	       (index (string-contains-ci data "2A864886FC6B04" 0)
		      (string-contains-ci data "2A864886FC6B04" index)))
	      ((not index))
	    (let ((scp (->integer (substring data (+ index 14) (index 16)) 16))
		  (v   (->integer (substring data (+ index 16) (index 18)) 16)))
	      (bytevector-u8-set! protocol scp i)))))
      (let* ((context (gp:make-secure-channel-context key-version key-id
						      :option option))
	     (rsp (send-apdu (gp:initialize-update context))))
	(when (and (not option) (> (bytevector-length rsp) 12))
	  (let* ((scp (bitwise-and (bytevector-u8-ref rsp 11) #xFF))
		 (v   (bytevector-u8-ref protocol scp)))
	    (when (positive? v) (sc-context-option-set! context v))))
	(unless (if (and (or (not enc-key) (not mac-key) (not dek-key))
			 (*master-keys*))
		    (gp:authenticate-card/keys context rsp
					       (*master-keys*)
					       derive-key)
		    (gp:authenticate-card context rsp
					  (pcsc:ensure-bytevector enc-key)
					  (pcsc:ensure-bytevector mac-key)
					  (pcsc:ensure-bytevector dek-key)
					  derive-key))
	  (raise-channel-error
	   'channel
	   "card could not be authenicated with the supplied keys!"
	   "Authentication failed"))
	(let1 result (send-apdu (gp:external-authenticate context security))
	  ;; set current security context
	  (*current-sc* context)
	  result))))

  (define-command (close-channel)
    "close-channel\n\nCloses current secure channel"
    (*current-sc* #f)
    #;
    (when (*current-sc*)
      (let1 resp (send-apdu #vu8(#x00 #x70 #x80 #x00))
	(*current-sc* #f)
	resp)))

  (define-command (delete aid :key (cascade #f) (token #f))
    "delete aid :key cascade token\n\n\
     Deletes specified application.\n\
     * cascade: if this is not #f, then this deletes all dependencies.\n\
     * token:   delete token. (tag '9E')"
    (define (get-data)
      (call-with-bytevector-output-port
       (lambda (out)
	 (define (emit-bv bv)
	   (put-u8 out (bytevector-length bv))
	   (put-bytevector out bv))
	 (emit-bv (pcsc:ensure-bytevector aid))
	 (when token
	   (put-u8 out #x9E)
	   (emit-bv (pcsc:ensure-bytevector token))))))
    (let ((p2 (if cascade #vu8(#x80) #vu8(#x00)))
	  (data   (get-data))
	  (lc&tag (make-bytevector 2 #x4F)))
      (bytevector-u8-set! lc&tag 0 (+ (bytevector-length data) 1))
      (send-apdu (bytevector-append
		  #vu8(#x80 #xE4 #x00)
		  p2
		  lc&tag
		  data))))


)