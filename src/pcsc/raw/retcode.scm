;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/raw/retcode - return codes of PC/SC
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

(library (pcsc raw retcode)
    (export *scard-s-success*
	    *scard-e-cancelled*
	    *scard-e-cant-dispose*
	    *scard-e-insufficient-buffer*
	    *scard-e-invalid-atr*
	    *scard-e-invalid-handle*
	    *scard-e-invalid-parameter*
	    *scard-e-invalid-target*
	    *scard-e-invalid-value*
	    *scard-e-no-memory*
	    *scard-f-comm-error*
	    *scard-f-internal-error*
	    *scard-f-unknown-error*
	    *scard-f-waited-too-long*
	    *scard-e-unknown-reader*
	    *scard-e-timeout*
	    *scard-e-sharing-violation*
	    *scard-e-no-smartcard*
	    *scard-e-unknown-card*
	    *scard-e-proto-mismatch*
	    *scard-e-not-ready*
	    *scard-e-system-cancelled*
	    *scard-e-not-transacted*
	    *scard-e-reader-unavailable*
	    *scard-w-unsupported-card*
	    *scard-w-unresponsive-card*
	    *scard-w-unpowered-card*
	    *scard-w-reset-card*
	    *scard-w-removed-card*
	    *scard-e-pci-too-small*
	    *scard-e-reader-unsupported*
	    *scard-e-duplicate-reader*
	    *scard-e-card-unsupported*
	    *scard-e-no-service*
	    *scard-e-service-stopped*
	    *scard-e-no-readers-available*
	    *scard-e-unsupported-feature*

	    return-code-success?
	    return-code-infomational?
	    return-code-warning?
	    return-code-error?
	    ;; utility
	    error-code->string
	    define-error-code
	    )
    (import (rnrs)
	    (only (sagittarius) define-constant format))

  (define (sev-bits n) (bitwise-arithmetic-shift-right n 30))
  ;; from SCardErr.h
  (define (return-code-success? code)      (= (sev-bits code) #b00))
  (define (return-code-infomational? code) (= (sev-bits code) #b01))
  (define (return-code-warning? code)      (= (sev-bits code) #b10))
  (define (return-code-error? code)        (= (sev-bits code) #b11))

  (define *error-code-table* (make-eqv-hashtable 128))
  (define (add-error-code-translation! code message)
    (hashtable-set! *error-code-table* code message))
  (define (error-code->string code)
    (cond ((hashtable-ref *error-code-table* code #f))
	  (else (format "Unknown error 0x%X" code))))

  (define-syntax define-error-code
    (lambda (x)
      (syntax-case x ()
	((_ name code message)
	 #'(begin
	     (define-constant name code)
	     (add-error-code-translation! code message))))))
  (define-syntax define-error-codes
    (lambda (x)
      (syntax-case x ()
	((_) #'(values))
	((_ (name code message) . rest)
	 #'(begin
	     (define-error-code name code message)
	     (define-error-codes . rest))))))

  (define-error-codes
    (*scard-s-success*        #x00000000 "Command successful.")
    (*scard-f-internal-error* #x80100001 "Internal error.")
    (*scard-e-cancelled*      #x80100002 "Command cancelled.")
    (*scard-e-invalid-handle* #x80100003 "Invalid handle.")
    (*scard-e-invalid-parameter* #x80100004 "Invalid parameter given.")
    (*scard-e-invalid-target* #x80100005 "Invalid target given.")
    (*scard-e-no-memory*      #x80100006 "Not enough memory.")
    (*scard-f-waited-too-long* #x80100007 "Waited too long.")
    (*scard-e-insufficient-buffer* #x80100008 "Insufficient buffer.")
    (*scard-e-unknown-reader* #x80100009 "Unknown reader specified.")
    (*scard-e-timeout*        #x8010000a "Command timeout.")
    (*scard-e-sharing-violation* #x8010000b "Sharing violation.")
    (*scard-e-no-smartcard*   #x8010000c "No smart card inserted.")
    (*scard-e-unknown-card*   #x8010000d "Unknown card.")
    (*scard-e-cant-dispose*   #x8010000e "Cannot dispose handle.")
    (*scard-e-proto-mismatch* #x8010000f "Card protocol mismatch.")
    (*scard-e-not-ready*      #x80100010 "Subsystem not ready.")
    (*scard-e-invalid-value*  #x80100011 "Invalid value given.")
    (*scard-e-system-cancelled* #x80100012 "System cancelled.")
    (*scard-f-comm-error*     #x80100013 "RPC transport error.")
    (*scard-f-unknown-error*  #x80100014 "Unknown error.")
    (*scard-e-invalid-atr*    #x80100015 "Invalid ATR.")
    (*scard-e-not-transacted* #x80100016 "Transaction failed.")
    (*scard-e-reader-unavailable* #x80100017 "Reader is unavailable")
    (*scard-e-pci-too-small*  #x80100019 "PCI struct too small.")
    (*scard-e-reader-unsupported* #x8010001a "Reader is unsupported.")
    (*scard-e-duplicate-reader* #x8010001b "Reader already exists.")
    (*scard-e-card-unsupported* #x8010001c "Card is unsupported.")
    (*scard-e-no-service*     #x8010001d "Service not available")
    (*scard-e-service-stopped* #x8010001e "Service was stopped.")
    (*scard-e-unsupported-feature* #x8010001f "Feature not supported.")
    (*scard-e-no-readers-available*
     #x8010002e "Cannot find a smart card reader.")
    (*scard-w-unsupported-card* #x80100065 "Card is not supported.")
    (*scard-w-unresponsive-card* #x80100066 "Card is unresponsive.")
    (*scard-w-unpowered-card* #x80100067 "Card is unpowered.")
    (*scard-w-reset-card*     #x80100068 "Card was reset.")
    (*scard-w-removed-card*   #x80100069 "Card was removed."))

)