(import (rnrs)
	(pcsc operations gp)
	(pcsc operations control)
	(pcsc shell commands))
;; set your key here
(define key #x10101010101010101010101010101010)

(establish-context)
(card-connect)
(trace-on)
(select)
;; get card status (for nothing)
(print (invoke-command card-status))

;; open secure channel
(channel :security *security-level-mac* 
	 :option #x55
	 :key-version #x20
	 :enc-key key
	 :mac-key key
	 :dek-key key)

;; application get status of ISD
;; if the command is not the most top-level then
;; invoke-command must be used to run commands
(print (bytevector->hex-string (invoke-command get-status issuer)))
(print (bytevector->hex-string (invoke-command get-status applications)))
(print (bytevector->hex-string (invoke-command get-status loadfiles)))
(print (bytevector->hex-string (invoke-command get-status modules)))

(card-disconnect)
(release-context)