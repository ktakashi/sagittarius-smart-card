(import (rnrs) (pcsc))
;; if reader-name was #f, then card-connect procedure tries to find
;; available card reader automatically
;; the card reader list can be retrieved by card-list-readers procedure.
(define reader-name "OMNIKEY CardMan 5x21-CL 0")

(call-with-card-context
 (lambda (context)
   (let ((readers (card-list-readers context))      ;; get card readers
	 (groups (card-list-reader-groups context)) ;; get reader groups
	 (buf    (make-bytevector 256)))
     (for-each print readers)
     (for-each print groups)
     (let*-values (((card ap) (card-connect context reader-name
					    *scard-share-shared*
					    *scard-protocol-any*))
		   ((reader state protocol atr) (card-status card))
		   ;; card-transmit! card io request must have the
		   ;; same protocol as card connection. for this
		   ;; example we assume it's using T1.
		   ;; users can check which protocol it is with
		   ;; the return value of card-connect.
		   ((rl pci) (card-transmit! card *scard-pci-t1*
					     #vu8(0 #xA4 4 0 0)
					     buf)))
       ;; just print everything we've got
       (print reader)
       (print state)
       (print protocol)
       (print atr)
       (print (number->string (bytevector->integer buf 0 rl) 16))
       (print rl)
       (print pci)
       ;; connection must be disconnected. Don't forget!
       (card-disconnect! card *scard-leave-card*)))))