;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/raw/types.scm - types and variables for PC/SC
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

(library (pcsc raw types)
    (export *scard-autoallocate*

	    *scard-scope-user* *scard-scope-terminal* *scard-scope-system*

	    *scard-share-shared* *scard-share-exclusive* *scard-share-direct*

	    *scard-protocol-t0* *scard-protocol-t1* *scard-protocol-raw*
	    *scard-protocol-t15* *scard-protocol-any* *scard-protocol-undefined*

	    *scard-leave-card* *scard-reset-card* *scard-unpower-card*
	    *scard-eject-card*
	    
	    ;; types
	    scard-io-request create-pci
	    *scard-pci-t0* *scard-pci-t1* *scard-pci-raw*
	    )
    (import (rnrs)
	    (sagittarius)
	    (sagittarius ffi))

  ;; variables
  (define-constant *scard-autoallocate*  -1)
  (define-constant *scard-scope-user*     0)
  (define-constant *scard-scope-terminal* 1)
  (define-constant *scard-scope-system*   0)

  (define-constant *scard-share-exclusive* 1)
  (define-constant *scard-share-shared*    2)
  (define-constant *scard-share-direct*    3)

  (define-constant *scard-protocol-undefined* 0)
  (define-constant *scard-protocol-t0*        1)
  (define-constant *scard-protocol-t1*        2)
  (define-constant *scard-protocol-raw*       4)
  (define-constant *scard-protocol-t15*       8)
  (define-constant *scard-protocol-any* 
    (+ *scard-protocol-t0* *scard-protocol-t1*))

  (define-constant *scard-leave-card*   0)
  (define-constant *scard-reset-card*   1)
  (define-constant *scard-unpower-card* 2)
  (define-constant *scard-eject-card*   3)

  ;; types
  (define-c-struct scard-io-request
    (int protocol)
    (int pci-length))

  (define (create-pci protocol)
    (let ((st (allocate-c-struct scard-io-request)))
      (c-struct-set! st scard-io-request 'protocol protocol)
      (c-struct-set! st scard-io-request 'pci-length 
		     (size-of-c-struct scard-io-request))
      st))
  (define *scard-pci-t0*  (create-pci *scard-protocol-t0*))
  (define *scard-pci-t1*  (create-pci *scard-protocol-t1*))
  (define *scard-pci-raw* (create-pci *scard-protocol-raw*))
)