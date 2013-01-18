;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/raw/winscard.scm - PC/SC C API of winscard library.
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

;; the functions defined in winscard.h
;; for compatibility we only use the ones defined in pcsc-lite.
(library (pcsc raw scard)
    (export s-card-establish-context
	    s-card-release-context
	    s-card-is-valid-context
	    s-card-connect
	    s-card-reconnect
	    s-card-disconnect
	    s-card-begin-transaction
	    s-card-end-transaction
	    s-card-status
	    s-card-get-status-change
	    s-card-control
	    s-card-transmit
	    s-card-list-reader-groups
	    s-card-list-readers
	    s-card-free-memory
	    s-card-cancel
	    s-card-get-attrib
	    s-card-set-attrib

	    *scard-autoallocate*

	    *scard-scope-user* *scard-scope-terminal* *scard-scope-system*

	    *scard-share-shared* *scard-share-exclusive* *scard-share-direct*

	    *scard-protocol-t0* *scard-protocol-t1* *scard-protocol-raw*
	    *scard-protocol-t15* *scard-protocol-any* *scard-protocol-undefined*

	    *scard-leave-card* *scard-reset-card* *scard-unpower-card*
	    *scard-eject-card*
	    )
    (import (rnrs)
	    (sagittarius)
	    (sagittarius ffi)
	    (pcsc raw helper)
	    (srfi :13))

  (define-c-typedef void* SCARDCONTEXT)
  (define-c-typedef void* SCARDHANDLE)
  (define-c-typedef unsigned-long ulong)

  ;; context related
  (define-c-function ulong s-card-establish-context int void* void* void*)
  (define-c-function ulong s-card-release-context SCARDCONTEXT)
  (define-c-function ulong s-card-is-valid-context SCARDCONTEXT)

  ;; connection
  (define-c-function "A"
    ulong s-card-connect SCARDCONTEXT char* int int void* void*)
  (define-c-function ulong s-card-reconnect SCARDHANDLE int int int void*)
  (define-c-function ulong s-card-disconnect SCARDHANDLE int)

  ;; transaction
  (define-c-function ulong s-card-begin-transaction SCARDHANDLE)
  (define-c-function ulong s-card-end-transaction SCARDHANDLE int)

  ;; status
  (define-c-function "A" 
    ulong s-card-status SCARDHANDLE char* void* void* void* void* void*)
  (define-c-function "A"
    ulong s-card-get-status-change SCARDHANDLE int void* int)

  ;; send commands
  (define-c-function ulong s-card-control SCARDHANDLE void* int void* int void*)
  (define-c-function ulong s-card-transmit
    SCARDHANDLE void* void* int void* void* void*)

  ;; readers
  (define-c-function "A"
    ulong s-card-list-reader-groups SCARDCONTEXT char* void*)
  (define-c-function "A"
    ulong s-card-list-readers SCARDCONTEXT char* char* void*)

  ;; etc
  (define-c-function ulong s-card-free-memory SCARDCONTEXT void*)
  (define-c-function ulong s-card-cancel SCARDCONTEXT)
  (define-c-function ulong s-card-get-attrib SCARDHANDLE int void* void*)
  (define-c-function ulong s-card-set-attrib SCARDHANDLE int void* int)

  ;; some variables
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
  )