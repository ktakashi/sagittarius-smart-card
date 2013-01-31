;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/operations/apdu.scm - APDU utilities.
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

(library (pcsc operations apdu)
    (export sw->description decompose-apdu)
    (import (rnrs)
	    (sagittarius)
	    (sagittarius control))
  (define-constant *iso-7816-status-words*
    '((#x6200 . "No information given")
      (#x6281 . "Part of returned data may be corrupted")
      (#x6282 . "End of file or record reached before reading Ne bytes")
      (#x6283 . "Selected file deactivated")
      (#x6284 . "File control information not formatted")
      (#x6300 . "No information given")
      (#x6310 . "More data available")
      (#x6381 . "File filled up by the last write")
      (#x6400 . "Execution error")
      (#x6401 . "Immediate response required by the card")
      (#x6500 . "No information given")
      (#x6581 . "Memory failure")
      (#x6700 . "Length error")
      (#x6800 . "No information given")
      (#x6881 . "Logical channel not supported")
      (#x6882 . "Secure messaging not supported")
      (#x6883 . "Last command of the chain expected")
      (#x6884 . "Command chaining not supported")
      (#x6981 . "Command incompatible with file structure")
      (#x6982 . "Security state not satisfied")
      (#x6983 . "Authentication method blocked")
      (#x6984 . "Referenced data reversibly blocked (invalidated)")
      (#x6985 . "Usage conditions not satisfied")
      (#x6986 . "Command not allowed (no EF selected)")
      (#x6987 . "Expected secure messaging data objects missing")
      (#x6988 . "Secure messaging data objects incorrect")
      (#x6A00 . "Incorrect P1 or P2 parameters (general)")
      (#x6A80 . "Parameters in the data portion are incorrect")
      (#x6A81 . "Function not supported")
      (#x6A82 . "File not found")
      (#x6A83 . "Record not found")
      (#x6A84 . "Insufficient memory")
      (#x6A85 . "Lc inconsistent with TLV structure")
      (#x6A86 . "Incorrect P1 or P2 parameter")
      (#x6A87 . "Lc inconsistent with P1 or P2")
      (#x6A88 . "Referenced data not found")
      (#x6A89 . "File already exists")
      (#x6A8A . "DF name already exists")
      (#x6D00 . "Command (instruction) not supported")
      (#x6E00 . "Class not supported")
      (#x6F00 . "No precise diagnosis")
      (#x9000 . "OK")
      (#x9484 . "(Global Platform) Algorithm not supported")
      (#x9485 . "(Global Platform) Invalid Key Check Value")))

  (define (sw->description resp :optional (buffer-length #f))
    (let1 sw (bytevector-u16-ref resp 
				 (- (or buffer-length (bytevector-length resp))
				    2)
				 (endianness big))
      (cond ((assv sw *iso-7816-status-words*) => cdr)
	    (else 
	     (case (bitwise-and sw #xFF00)
	       ((#x6100)
		(format "SW2(~d) indicates the number of response bytes still available"
			(bitwise-and sw #x00FF)))
	       ((#x6C00)
		(format "Wrong length Le: SW2(~d) indicates the exact length"
			(bitwise-and sw #x00FF)))
	       (else (format "Unknown code [~X]" sw)))))))

  ;; FIXME use (binary pack) after 0.4.2 is released
  ;; returns 6 values, CLA INS P1 P2 Lc and data
  (define (decompose-apdu apdu)
    ;; APDU needs CLA INS P1 P2 Lc
    (when (< (bytevector-length apdu) 5)
      (assertion-violation 'decompose-apdu "invalid APDU length" apdu))
    (values (bytevector-u8-ref apdu 0) ;; CLA
	    (bytevector-u8-ref apdu 1) ;; INS
	    (bytevector-u8-ref apdu 2) ;; P1
	    (bytevector-u8-ref apdu 3) ;; P2
	    (bytevector-u8-ref apdu 4) ;; Lc
	    (bytevector-copy apdu 5)))

)