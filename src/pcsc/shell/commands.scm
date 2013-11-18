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
	    (rename (prog:aid->bytevector aid->bytevector))
	    retrieve-return-code
	    (rename (gp:*security-level-none* *security-level-none*)
		    (gp:*security-level-mac*  *security-level-mac*)
		    (gp:*security-level-enc*  *security-level-enc*)
		    (gp:*security-level-renc* *security-level-renc*))
	    ;; variables
	    ;; get-status and set-status
	    (rename (prog:+issuer+      issuer)
		    (prog:+application+ application)
		    (prog:+loadfile+    loadfile)
		    (prog:+module+      module))
	    ;; 
	    associated locked personalized secured selectable card-locked
	    terminated
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
	    (prefix (pcsc operations apdu) apdu:)
	    (prefix (pcsc operations program) prog:)
	    (sagittarius)
	    (sagittarius object)
	    (sagittarius control)
	    (match)
	    (binary pack)
	    (util file)
	    (tlv)
	    (only (crypto) MODE_ECB)
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

  (define-command (card-disconnect :optional (how pcsc:*scard-reset-card*))
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
    (check-card send-apdu)
    (prog:send-apdu (*current-connection*) apdu (*current-sc*)))

  (define-command (select :key (aid #vu8()))
    "select :key aid\n\n\
     Sends select command."
    (prog:select-application (*current-connection*)
			     :aid (prog:aid->bytevector aid)))

  (define-command (get-status type :key (aid #f) (contactless #f))
    "get-status types :key aid\n\n\
     Transmit GET STATUS command.\n  \
     * type: status type must be issuer, application, loadfile or module"
    (prog:get-status (*current-connection*) type
		     :aid (if aid (prog:aid->bytevector aid) #f)
		     :contactless contactless
		     :sc-context (*current-sc*)))

  ;; set status specific
  (define-constant associated   #x20)
  ;; p2 parameters
  (define-constant locked       #x83)
  (define-constant personalized #x0F)
  (define-constant secured      personalized)
  (define-constant selectable   #x07)
  (define-constant card-locked  #x7F)
  (define-constant terminated   #xFF)
  
  (define-command (set-status type control :optional (aid #f))
    "set-status type control [aid]\n\n\
     Transmit SET STATUS command.\n\
     type should be issuer, application or (application | associated).\n\
     control should be locked, personalized or secured, selectable, \
     card-locked or terminated.\n\
     These parameters are merely a byte so it can be just a legal number.\n\
     aid must be a valid AID."
    (prog:set-status (*current-connection*)
		     type control
		     :aid (if aid (prog:aid->bytevector aid) #vu8())
		     :sc-context (*current-sc*)))

  ;; issuer identification number
  (define-constant iin                      #x0042)
  (define-constant card-image-number        #x0045)
  (define-constant card-data                #x0066)
  (define-constant key-information-template #x00E0)
  (define-constant extended-card-recources  #xFF21)
  (define-constant cplc                     #x9F7F)

  (define-command (get-data record :optional (data #vu8(00)))
    "get-data record\n\n\
     Transmit GET DATA command.\n  \
     * record: P1 and P2 values (exact integer)."
    (let ((p1 (bitwise-and (bitwise-arithmetic-shift-right record 8) #xFF))
	  (p2 (bitwise-and record #xFF)))
      (send-apdu (apdu:compose-apdu #x80 #xCA p1 p2 data))))

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
    (define (open-secure-channel enc-key mac-key dek-key :optional (raise #t))
      (prog:open-secure-channel (*current-connection*)
				(pcsc:ensure-bytevector enc-key)
				(pcsc:ensure-bytevector mac-key)
				(pcsc:ensure-bytevector dek-key)
				:security-level security
				:key-id key-id 
				:key-version key-version
				:derive-key derive-key
				:option option
				:raise raise))
    ;; closes current channel if there is.
    (close-channel)
    (if (and (or (not enc-key) (not mac-key) (not dek-key)) (*master-keys*))
	;; do manually
	(let loop ((keys (*master-keys*)))
	  (if (null? keys)
	      (prog:channel-error 'channel 
				  "Could not authenticate with given keys")
	      (let*-values (((enc-key mac-key dek-key)
			     (match (car keys)
			       ((enc) (value enc enc enc))
			       ((enc mac dek) (values enc mac dek))
			       (_ (error 'channel "invalid key list was given"
					 (car keys) (*master-keys*)))))
			    ((context result)
			     (open-secure-channel enc-key mac-key dek-key #f)))
		(if context
		    (begin (*current-sc* context) result)
		    (loop (cdr keys))))))
	(let-values (((context result)
		      (open-secure-channel enc-key mac-key dek-key)))
	  (*current-sc* context)
	  result)))

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
    (prog:delete-application (*current-connection*) 
			     (prog:aid->bytevector aid)
			     :cascade cascade
			     :token (if token 
					(pcsc:ensure-bytevector token)
					#f)
			     :sc-context (*current-sc*)))

  (define-command (put-key key-version key-identifier keys
			   :key (encrypt #t) (mode MODE_ECB))
    "put-key key-version key-identifier keys :key (encrypt #t)\n\n\
     Puts given keys. Keys must a list of following form.\n\
     eg) keys = '((#x80 <key-value> <kcv>))\n    \
         key-value and kcv can be either bytevector or integer.\n\
     * encrypt: if this is #f, then the command doesn't encrypt the keys.\n\
     * mode   : chaining mode."
    (when (null? keys)
      (assertion-violation 'put-key "at least one key is required"))
    ;; for now don't support multiple put key commands, means no RSA keys
    (let ((p1 (bitwise-and key-version #x7F))
	  (p2 (bitwise-ior (if (null? (cdr keys)) 0 1) key-identifier)))
      (define (compose-key-data keys)
	(define (key->bytevector key)
	  (define (maybe-encrypt data)
	    (if (and encrypt (*current-sc*))
		(gp:encrypt-data data (~ (*current-sc*) 'dek-session-key) mode)
		data))
	  ;; we don't support 'FF' extended key type
	  (match key
	    ((type key kcv)
	     (let* ((key (maybe-encrypt (pcsc:ensure-bytevector key)))
		    (kcv (pcsc:ensure-bytevector kcv))
		    (key-len (bytevector-length key))
		    (kcv-len (bytevector-length kcv))
		    ;; FIXME
		    (bv (make-bytevector (+ key-len kcv-len 3))))
	       ;; TODO encode key length to ber-length
	       ;; for now assume it's less than #x80
	       (bytevector-u8-set! bv 0 type)
	       (bytevector-u8-set! bv 1 key-len)
	       (bytevector-copy! key 0 bv 2 key-len)
	       (bytevector-u8-set! bv (+ 2 key-len) kcv-len)
	       (bytevector-copy! kcv 0 bv (+ 3 key-len) kcv-len)
	       bv))
	    (_
	     (error 'put-key "invalid format key"))))
	(apply bytevector-append (make-bytevector 1 key-version)
	       (map key->bytevector keys)))
      (let1 key-data (compose-key-data keys)
	(send-apdu (apdu:compose-apdu #x80 #xD8 p1 p2 key-data)))))
)