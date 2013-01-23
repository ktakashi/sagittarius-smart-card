;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/key/rim.scm - RIM key derivation
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

(library (pcsc key rim)
    (export derive-key-rim
	    *device-pin*)
    (import (rnrs)
	    (pcsc operations gp)
	    (only (pcsc shell commands) aid->bytevector)
	    (srfi :39)
	    (sagittarius control)
	    (crypto))

  (define *device-pin* (make-parameter #f))
  (define (derive-key-rim master answer indicator)
    (let ((derive-data (make-bytevector 16))
	  (device-pin  (*device-pin*)))
      (unless device-pin
	(assertion-violation 'derive-pin-rim "device pin is not set"))
      (set! device-pin (aid->bytevector device-pin))
      (bytevector-u8-set! derive-data 0 1)
      (bytevector-u8-set! derive-data 1
			  (cond ((= indicator *key-indicator-enc*) #x82)
				((= indicator *key-indicator-mac*) #x1)
				((= indicator *key-indicator-dek*) #x81)
				(else (error 'derive-key-rim 
					     "invalid key indicator is given"
					     indicator))))
      (bytevector-copy! device-pin 0 derive-data 2 
			(bytevector-length device-pin))
      (derive-key derive-data master MODE_CBC)))

)