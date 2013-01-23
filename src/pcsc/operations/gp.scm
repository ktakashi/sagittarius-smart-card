;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/operations/gp - Global platform stuff
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

(library (pcsc operations gp)
    (export make-secure-channel-context
	    ;; gp operations
	    initialize-update
	    authenticate-card
	    external-authenticate

	    ;; key deriver
	    derive-key      ;; underlying procedure
	    derive-key-none

	    ;; crypto
	    encrypt-data

	    ;; APDU encoder
	    encode-apdu
	    
	    ;; constant variables
	    *key-indicator-enc* 
	    *key-indicator-mac*
	    *key-indicator-dek*
	    *security-level-none*
	    *security-level-mac*
	    *security-level-enc*
	    *security-level-renc*

	    sc-context-option-set!)
    (import (rnrs)
	    (srfi :39)
	    (clos user)
	    (crypto)
	    (util bytevector)
	    (sagittarius)
	    (sagittarius control)
	    (pcsc operations control))

  (define-class <secure-channel-context> ()
    ((challenge   :init-keyword :challenge   :reader sc-challenge)
     (key-version :init-keyword :key-version :reader sc-key-version)
     (key-id      :init-keyword :key-id      :reader sc-key-id)
     (option      :init-keyword :option      :reader sc-option
		  :writer sc-context-option-set!)
     (security-level :init-value 'none   :accessor sc-security-level)
     (scp         :init-value #f :accessor sc-scp)
     (card-challenge :init-value #f :accessor sc-card-challenge)
     (iv          :init-value (make-bytevector 8) :accessor sc-iv)
     ;; static keys
     (enc-key     :init-value #f :accessor sc-enc-key)
     (mac-key     :init-value #f :accessor sc-mac-key)
     (dek-key     :init-value #f :accessor sc-dek-key)
     ;; session keys
     (enc-session-key :init-value #f :accessor sc-enc-session-key)
     (mac-session-key :init-value #f :accessor sc-mac-session-key)
     (dek-session-key :init-value #f :accessor sc-dek-session-key)
     ))

  (define (make-secure-channel-context 
	   key-version key-id
	   :key (challenge (make-bytevector 8)) (option #f))
    (make <secure-channel-context> :key-version key-version :key-id key-id
	  :challenge challenge :option option))

  (define-syntax bv-set!
    (syntax-rules ()
      ((_ bv i v) (bytevector-u8-set! bv i v))))
  (define-syntax bv-ref
    (syntax-rules ()
      ((_ bv i) (bytevector-u8-ref bv i))))

  (define (initialize-update context)
    (let1 apdu (make-bytevector 13)
      (bv-set! apdu 0 #x80)
      (bv-set! apdu 1 #x50)
      (bv-set! apdu 2 (sc-key-version context))
      (bv-set! apdu 3 (sc-key-id context))
      (bv-set! apdu 4 #x08)
      (bytevector-copy! (sc-challenge context) 0 apdu 5 8)
      apdu))

  (define (authenticate-card context card-answer enc-key mac-key dek-key
			     derive-key)
    (sc-scp context (bv-ref card-answer 11))
    (sc-card-challenge context (bytevector-copy card-answer 12 20))
    (derive-static-keys! context enc-key mac-key dek-key card-answer derive-key)
    (derive-session-key! context card-answer)
    (verify-card-cryptogram context card-answer))

  (define (verify-card-cryptogram context card-answer)
    (let ((card-cryptogram (bytevector-copy card-answer 20 28))
	  (authentication-data (make-bytevector 24 0)))
      (bytevector-copy! (sc-challenge context) 0 authentication-data 0 8)
      (bytevector-copy! (sc-card-challenge context) 0 authentication-data 8 8)
      (bv-set! authentication-data 16 #x80)
      (let* ((cipher-text (encrypt-data authentication-data 
					(sc-enc-session-key context)
					MODE_CBC))
	     (start (- (bytevector-length cipher-text) 8))
	     (reconstructed-cryptogram (bytevector-copy cipher-text start)))
	(bytevector=? reconstructed-cryptogram card-cryptogram))))

  (define (derive-session-key! context card-answer)
    (define (scp01)
      (let1 data (make-bytevector 16)
	(bytevector-copy! (sc-card-challenge context) 4 data 0 4)
	(bytevector-copy! (sc-challenge context) 0 data 4 4)
	(bytevector-copy! (sc-card-challenge context) 0 data 8 4)
	(bytevector-copy! (sc-challenge context) 4 data 12 4)
	(sc-enc-session-key context 
			    (derive-key data (sc-enc-key context) MODE_ECB))
	(sc-mac-session-key context 
			    (derive-key data (sc-mac-key context) MODE_ECB))
	(sc-dek-session-key context 
			    (derive-key data (sc-dek-key context) MODE_ECB))))
    (define (scp02)
      (let1 data (make-bytevector 16)
	(bv-set! data 0 1)
	(bv-set! data 1 #x82)
	(bytevector-copy! card-answer 12 data 2 2)
	(sc-enc-session-key context
			    (derive-key data (sc-enc-key context) MODE_CBC))
	;; reuse
	(bv-set! data 1 1)
	(sc-mac-session-key context
			    (derive-key data (sc-mac-key context) MODE_CBC))
	;; reuse
	(bv-set! data 1 #x81)
	(sc-dek-session-key context
			    (derive-key data (sc-dek-key context) MODE_CBC))))
    (case (sc-scp context)
      ((1) (scp01))
      ((2) (scp02))))

  (define-constant *key-indicator-enc* 1)
  (define-constant *key-indicator-mac* 2)
  (define-constant *key-indicator-dek* 3)

  (define (derive-static-keys! context enc-key mac-key dek-key card-answer
			       derive-key)
    (sc-enc-key context (derive-key enc-key card-answer *key-indicator-enc*))
    (sc-mac-key context (derive-key mac-key card-answer *key-indicator-mac*))
    (sc-dek-key context (derive-key dek-key card-answer *key-indicator-dek*))
    )

  (define (derive-key-none master card-answer indicator) master)

  (define (encrypt-data data key mode)
    (define key-length 24)
    (let ((key-bytes (make-bytevector key-length))
	  (master-length (bytevector-length key)))
      (let loop ((offset 0))
	(when (< offset key-length)
	  (let1 tocopy (min master-length (- key-length offset))
	    (bytevector-copy! key 0 key-bytes offset tocopy)
	    (loop (+ offset tocopy)))))
      (let* ((des3-key (generate-secret-key DES3 key-bytes))
	     (des3-cipher (cipher DES3 des3-key :mode mode :padder #f
				  :iv (make-bytevector 8))))
	(encrypt des3-cipher data))))
  (define derive-key encrypt-data)

  (define-constant *security-level-none* 0)
  (define-constant *security-level-mac*  1)
  (define-constant *security-level-enc*  3)
  (define-constant *security-level-renc* #x33)

  (define (external-authenticate context level :optional (sample #f))
    (define template-apdu #vu8(#x80 #x82 #x00 0 #x08 0 0 0 0 0 0 0 0))
    (sc-security-level context level)
    (let ((apdu-bytes (bytevector-copy template-apdu))
	  (data (make-bytevector 24)))
      ;; prepare apdu-bytes
      (bv-set! apdu-bytes 2 level)

      (bytevector-copy! (sc-card-challenge context) 0 data 0 8)
      (bytevector-copy! (sc-challenge context) 0 data 8 8)

      (bv-set! data 16 #x80)
      (let1 cipher-text (encrypt-data data (sc-enc-session-key context)
				      MODE_CBC)
	(bytevector-copy! cipher-text (- (bytevector-length cipher-text) 8)
			  apdu-bytes 5 8)
	(encode-apdu context apdu-bytes *security-level-mac*))))

  (define (encode-apdu context apdu 
		       :optional 
		       (security (and context (sc-security-level context))))
    ;; determine which encryption mode will be used
    ;; The SELECT command is never encrypted
    (define (is-select? apdu)
      (and (= (bv-ref apdu 0) #x00) (= (bv-ref apdu 1) #xA4)
	   (sc-security-level context *security-level-none*)
	   apdu))
    (define (icv-encrypted? context)
      (not (zero? (bitwise-and (sc-option context) #x10))))
    (define (sign-data-full-des-mac bv)
      (let1 cipher (encrypt-data bv (sc-mac-session-key context) MODE_CBC)
	(bytevector-copy cipher (- (bytevector-length cipher) 8) 8)))
    (define (sign-data-retail-mac bv)
      (let* ((key (sc-mac-session-key context))
	     (data (bytevector-copy bv 0 (- (bytevector-length bv) 8)))
	     (last-block (bytevector-copy bv (bytevector-length data))))
	;; if we have more than 8 bytes, encrypt data block using DED with the
	;; left key half
	(when (positive? (bytevector-length data))
	  ;; first encrypt the first n-1 blocks using the left key half
	  (let* ((encrypted (encrypt-data data
					  (bytevector-copy key 0 8)
					  MODE_CBC))
		 (intermediate (bytevector-copy 
				encrypted 
				(- (bytevector-length encrypted) 8))))
	    ;; xor the last block of the intermediate result with the
	    ;; last block
	    (bytevector-xor! last-block last-block intermediate)))
	(encrypt-data last-block key MODE_ECB)))

    (define (compute-enciphered-data len)
      (define (padding bv)
	(define (rec pad-len)
	  (if (case (sc-scp context) ((1) (not (zero? pad-len))) (else #t))
	      (let1 pad (make-bytevector pad-len)
		(bv-set! pad 0 #x80)
		(bytevector-append bv pad))
	      bv))
	(rec (- 8 (mod (bytevector-length bv) 8))))
      (padding (call-with-bytevector-output-port
		(lambda (out)
		  (case (sc-scp context)
		    ((1)
		     ;; LE becomes part of the data
		     (if (<= (bytevector-length apdu) 4)
			 (put-u8 out 0)
			 (begin (put-u8 out len)
				;; clear command data
				(put-bytevctor out apdu 5 len))))
		    ((2) 
		     ;; clear command data
		     (when (> (bytevector-length apdu) 4)
		       (put-bytevctor out apdu 5 len))))))))
    (or (and (not context) apdu)
	(is-select? apdu)
	(and (= security *security-level-none*) apdu)
	(let* ((apdu-len (bytevector-length apdu))
	       (sign-len (* (div (+ apdu-len 8) 8) 8))
	       (sign-data (make-bytevector sign-len))
	       (len (if (> apdu-len 4) (bitwise-and (bv-ref apdu 4) #xFF) 0)))
	  (bytevector-copy! apdu 0 sign-data 0 apdu-len)
	  ;; set secure message bit in class byte
	  (bv-set! sign-data 0 (bitwise-ior (bv-ref sign-data 0) #x04))
	  ;; new LC = data length + 8 bytes cryptogram
	  (bv-set! sign-data 4 (+ len 8))
	  ;; pad sign-data with "80 00 00..."
	  (bv-set! sign-data apdu-len #x80)
	  ;; xor first block with IV
	  (bytevector-xor! sign-data sign-data (sc-iv context))
	  (let1 signature (case (sc-scp context)
			    ((1) (sign-data-full-des-mac sign-data))
			    ((2) (sign-data-retail-mac sign-data))
			    (else (error 'encode-apdu "invalid SCP")))
	    ;; result signature is next iv
	    (bytevector-copy! signature 0 (sc-iv context) 0 8)
	    ;; If the implementation option indicates it, we will
	    ;; encrypt the ICV with the lefe key half of the session
	    ;; MAC key
	    (when (icv-encrypted? context)
	      (let1 key (bytevector-copy (sc-mac-session-key context) 0 8)
		(sc-iv context (encrypt-data (sc-iv context) key MODE_ECB))))
	    ;; signed data = data + signature
	    (let* ((offset (if (<= apdu-len 4) 1 0))
		   (signed-apdu (make-bytevector (+ apdu-len 8 offset))))
	      (bytevector-copy! apdu 0 signed-apdu 0 apdu-len)
	      (bytevector-copy! signature 0
				signed-apdu (+ apdu-len offset)
				(bytevector-length signature))
	      (bv-set! signed-apdu 0 
		       (bitwise-ior (bv-ref signed-apdu 0) #x04))
	      (bv-set! signed-apdu 4 (+ (bv-ref signed-apdu 4) 8))
	      (if (= security *security-level-mac*)
		  signed-apdu
		  (let* ((ciphered-data (encrypt-data
					 (compute-enciphered-data len)
					 (sc-enc-session-key context)
					 MODE_CBC))
			 (ciphered-apdu (make-bytevector 
					 (+ 5
					    (bytevector-length ciphered-data)
					    8))))
		    (bytevector-copy! signed-apdu 0 ciphered-apdu 0 4)
		    (bv-set! ciphered-apdu 4 
			     (+ (bytevector-length ciphered-data) 8))
		    (bytevector-copy! ciphered-data 0 ciphered-apdu 5
				      (bytevector-length ciphered-data))
		    (bytevector-copy! signed-apdu
				      (+ (bytevector-length signed-apdu)
					 8)
				      ciphered-apdu
				      (+ (bytevector-length ciphered-data)
					 5)
				      8)
		    ciphered-apdu)))))))
  
)