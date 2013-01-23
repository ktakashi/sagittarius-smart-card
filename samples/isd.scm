(import (rnrs)
	(pcsc operations gp)
	(pcsc operations control)
	(pcsc shell commands))
;; set your key here
(define key #x10101010101010101010101010101010)

(establish-context)
(card-connect #f)
(trace-on)
(select)
;; get card status (for nothing)
(card-status)

;; open secure channel
(channel :security *security-level-mac* 
	 :option #x55
	 :key-version #x20
	 :enc-key key
	 :mac-key key
	 :dek-key key)

;; application get status of ISD
(get-status applications)

(card-disconnect)
(release-context)