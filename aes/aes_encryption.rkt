#lang racket

(require math/number-theory)
(require math/matrix)
(require rackunit)
(require "ffarith.rkt")


;;****************************************************
;;******************************************************************************
;; Utilities & misc for lists/bytes/hex/etc
;;******************************************************************************
;;****************************************************
; pair-chars : list of chars -> list with pair char strings
(define (pair-chars l)
  (cond
    [(empty? l)
     empty]
    [(even? (length l))
     (cons
      (list->string (take l 2))
      (pair-chars (rest (rest l))))]
    [else
     (error "strpair must receive an even length str")]))

(check-equal? (pair-chars (list #\a #\b #\c #\d))
              (list "ab" "cd"))

; 0xbytes : hex-string -> list of hex bytes
(define (0x str)
  (map string->number 
       (for/list ([c (pair-chars (string->list str))])
         (string-append "#x" c))))

(check-equal? (0x "0102030405")
              (list 1 2 3 4 5))

(check-equal? (0x "0a0b0c0d0e")
              (list #xa #xb #xc #xd #xe))

; returns list from element ith -> j-1th 
; [ith, ..., jth] (0 based)
(define (sublist l i j)
  (drop (take l j) i))

(check-equal? (sublist (list 1) 0 1) (list 1))
(check-equal? (sublist (list 1 2 3 4) 1 3) (list 2 3))

; nth-word : list-of-bytes -> list of bytes 4 long
; Extracts a "word" from a list of bytes
(define (nth-word byte-list wnum)
  (sublist byte-list (* wnum 4) (* (add1 wnum) 4)))

(check-equal? (nth-word (list 0 1 2 3
                              4 5 6 7
                              8 9 10 11
                              12 13 14 15)
                        3)
              (list 12 13 14 15))
(check-equal? (nth-word (list 0 1 2 3
                              4 5 6 7
                              8 9 10 11
                              12 13 14 15)
                        1)
              (list 4 5 6 7))

; Reverses a list of bytes on a word level
(define (word-rev lob)
  (cond
    [(> (length lob) 4)
     (append (drop lob (- (length lob) 4))
             (word-rev (take lob (- (length lob) 4))))]
    [(= 4 (length lob))
     lob]
    [else
     (error 'word-rev "invalid length")]))

(check-equal? (word-rev (list 1 2 3 4)) (list 1 2 3 4))
(check-equal? (word-rev (list 1 2 3 4
                              5 6 7 8)) 
              (list 5 6 7 8
                    1 2 3 4))
(check-equal? (word-rev (list 1 2 3 4
                              5 6 7 8
                              9 10 11 12)) 
              (list 9 10 11 12
                    5 6 7 8
                    1 2 3 4))

;;****************************************************
;;******************************************************************************
;; AES Struct & Constants
;;******************************************************************************
;;****************************************************
(struct AES (key)
  #:guard (λ (key type-name)
            (if (and (andmap (λ (x) (< -1 x 256)) key)
                     (or (= (length key) 16)
                         (= (length key) 24)
                         (= (length key) 32)))
                key
                (error type-name 
                       "invalid key: ~e" 
                       key))))

(define Nb 4)

(define (AES-Nk aes)
  (define len (length (AES-key aes)))
  (cond
    [(= len 16) 4]
    [(= len 24) 6]
    [(= len 32) 8]
    [else AES-Nk (error "invalid key")]))

(define (AES-Nr aes)
  (define Nk (AES-Nk aes))
  (cond
    [(= 4 Nk) 10]
    [(= 6 Nk) 12]
    [(= 8 Nk) 14]))

(check-equal? (AES-Nk (AES (list #x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6
                                 #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c))) 
              4)
(check-equal? (AES-Nr (AES (list #x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6
                                 #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c))) 
              10)

(check-equal? (AES-Nk (AES (list #x8e #x73 #xb0 #xf7 #xda #x0e #x64 #x52 
                                 #xc8 #x10 #xf3 #x2b #x80 #x90 #x79 #xe5 
                                 #x62 #xf8 #xea #xd2 #x52 #x2c #x6b #x7b))) 
              6)
(check-equal? (AES-Nr (AES (list #x8e #x73 #xb0 #xf7 #xda #x0e #x64 #x52 
                                 #xc8 #x10 #xf3 #x2b #x80 #x90 #x79 #xe5 
                                 #x62 #xf8 #xea #xd2 #x52 #x2c #x6b #x7b))) 
              12)

(check-equal? (AES-Nk (AES (list #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe
                                 #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                                 #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7 
                                 #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4)))
              8)
(check-equal? (AES-Nr (AES (list #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe
                                 #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                                 #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7 
                                 #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4)))
              14)

(check-exn exn:fail? (λ () (AES 128 "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")))

(define sbox 
  (matrix [[ #x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76 ] 
           [ #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0 ] 
           [ #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15 ] 
           [ #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75 ] 
           [ #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84 ] 
           [ #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf ] 
           [ #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8 ] 
           [ #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2 ] 
           [ #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73 ] 
           [ #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb ] 
           [ #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79 ] 
           [ #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08 ] 
           [ #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a ] 
           [ #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e ] 
           [ #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf ] 
           [ #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16 ]])) 

(define inv-sbox 
  (matrix [[ #x52 #x09 #x6a #xd5 #x30 #x36 #xa5 #x38 #xbf #x40 #xa3 #x9e #x81 #xf3 #xd7 #xfb ] 
           [ #x7c #xe3 #x39 #x82 #x9b #x2f #xff #x87 #x34 #x8e #x43 #x44 #xc4 #xde #xe9 #xcb ] 
           [ #x54 #x7b #x94 #x32 #xa6 #xc2 #x23 #x3d #xee #x4c #x95 #x0b #x42 #xfa #xc3 #x4e ] 
           [ #x08 #x2e #xa1 #x66 #x28 #xd9 #x24 #xb2 #x76 #x5b #xa2 #x49 #x6d #x8b #xd1 #x25 ] 
           [ #x72 #xf8 #xf6 #x64 #x86 #x68 #x98 #x16 #xd4 #xa4 #x5c #xcc #x5d #x65 #xb6 #x92 ] 
           [ #x6c #x70 #x48 #x50 #xfd #xed #xb9 #xda #x5e #x15 #x46 #x57 #xa7 #x8d #x9d #x84 ] 
           [ #x90 #xd8 #xab #x00 #x8c #xbc #xd3 #x0a #xf7 #xe4 #x58 #x05 #xb8 #xb3 #x45 #x06 ] 
           [ #xd0 #x2c #x1e #x8f #xca #x3f #x0f #x02 #xc1 #xaf #xbd #x03 #x01 #x13 #x8a #x6b ] 
           [ #x3a #x91 #x11 #x41 #x4f #x67 #xdc #xea #x97 #xf2 #xcf #xce #xf0 #xb4 #xe6 #x73 ] 
           [ #x96 #xac #x74 #x22 #xe7 #xad #x35 #x85 #xe2 #xf9 #x37 #xe8 #x1c #x75 #xdf #x6e ] 
           [ #x47 #xf1 #x1a #x71 #x1d #x29 #xc5 #x89 #x6f #xb7 #x62 #x0e #xaa #x18 #xbe #x1b ] 
           [ #xfc #x56 #x3e #x4b #xc6 #xd2 #x79 #x20 #x9a #xdb #xc0 #xfe #x78 #xcd #x5a #xf4 ] 
           [ #x1f #xdd #xa8 #x33 #x88 #x07 #xc7 #x31 #xb1 #x12 #x10 #x59 #x27 #x80 #xec #x5f ] 
           [ #x60 #x51 #x7f #xa9 #x19 #xb5 #x4a #x0d #x2d #xe5 #x7a #x9f #x93 #xc9 #x9c #xef ] 
           [ #xa0 #xe0 #x3b #x4d #xae #x2a #xf5 #xb0 #xc8 #xeb #xbb #x3c #x83 #x53 #x99 #x61 ] 
           [ #x17 #x2b #x04 #x7e #xba #x77 #xd6 #x26 #xe1 #x69 #x14 #x63 #x55 #x21 #x0c #x7d ]]))


;rcon is 1-based so the first entry is just a place holder 
(define rcon 
  (list empty             (list #x01 0 0 0) (list #x02 0 0 0) (list #x04 0 0 0)
        (list #x08 0 0 0) (list #x10 0 0 0) (list #x20 0 0 0) (list #x40 0 0 0)
        (list #x80 0 0 0) (list #x1B 0 0 0) (list #x36 0 0 0) (list #x6C 0 0 0)
        (list #xD8 0 0 0) (list #xAB 0 0 0) (list #x4D 0 0 0) (list #x9A 0 0 0)
        (list #x2F 0 0 0) (list #x5E 0 0 0) (list #xBC 0 0 0) (list #x63 0 0 0)
        (list #xC6 0 0 0) (list #x97 0 0 0) (list #x35 0 0 0) (list #x6A 0 0 0)
        (list #xD4 0 0 0) (list #xB3 0 0 0) (list #x7D 0 0 0) (list #xFA 0 0 0)
        (list #xEF 0 0 0) (list #xC5 0 0 0) (list #x91 0 0 0) (list #x39 0 0 0)
        (list #x72 0 0 0) (list #xE4 0 0 0) (list #xD3 0 0 0) (list #xBD 0 0 0)
        (list #x61 0 0 0) (list #xC2 0 0 0) (list #x9F 0 0 0) (list #x25 0 0 0)
        (list #x4A 0 0 0) (list #x94 0 0 0) (list #x33 0 0 0) (list #x66 0 0 0)
        (list #xCC 0 0 0) (list #x83 0 0 0) (list #x1D 0 0 0) (list #x3A 0 0 0)
        (list #x74 0 0 0) (list #xE8 0 0 0) (list #xCB 0 0 0) (list #x8D 0 0 0)))

;;****************************************************
;;******************************************************************************
;; AES Key Expansion
;;******************************************************************************
;;****************************************************

(define (sbox-sub b)
  (matrix-ref 
   sbox
   (bitwise-bit-field b 4 8)
   (bitwise-bit-field b 0 4)))

(check-equal? (sbox-sub #x53) #xed)
(check-equal? (sbox-sub #x00) #x63)
(check-equal? (sbox-sub #x6a) #x02)
(check-equal? (sbox-sub #x4c) #x29)


;;****************************************************
; SubBytes (sb) : list-of-bytes -> list-of-bytes
;;****************************************************
; takes list of bytes, performs sbox sub
(define (sb lob)
  (map sbox-sub lob))

(check-equal? (sb '(#x53 #x4c #x13 #xff)) '(#xed #x29 #x7d #x16))

;;****************************************************
; RotWord (rw) : list-of-bytes -> list-of-bytes
;;****************************************************
; takes list of bytes 4 long, and rotates them cyclicly
(define (rw lob)
  (append (rest lob) (list (first lob))))

(check-equal? (rw '(1 2 3 4)) '(2 3 4 1))

;;****************************************************
; KeyExpansion (ke) : AES -> listof-listof-bytes
;;****************************************************
(define (ke aes)
  (define key (AES-key aes))
  (define Nk (AES-Nk aes))
  (define Nr (AES-Nr aes))
  (define w (take key (* 4 Nk)))
  (word-rev 
   (for/fold ([expansion (word-rev w)]) 
     ([i (range Nk (* Nb (add1 Nr)))])
     (let* ([head (nth-word expansion 0)]
            [Nkth (nth-word expansion (sub1 Nk))]
            [temp (cond
                    [(zero? (modulo i Nk))
                     (map bitwise-xor 
                          (sb (rw head))
                          (list-ref rcon (quotient i Nk)))]
                    [(and (> Nk 6) (= 4 (modulo i Nk)))
                     (sb head)]
                    [else
                     head])])
       (append (map bitwise-xor Nkth temp)
               expansion)))))

(check-equal? (ke (AES (list #x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6
                             #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c)))
              (list  #x2b #x7e #x15 #x16 #x28 #xae #xd2 #xa6
                     #xab #xf7 #x15 #x88 #x09 #xcf #x4f #x3c
                     #xa0 #xfa #xfe #x17 #x88 #x54 #x2c #xb1
                     #x23 #xa3 #x39 #x39 #x2a #x6c #x76 #x05
                     #xf2 #xc2 #x95 #xf2 #x7a #x96 #xb9 #x43
                     #x59 #x35 #x80 #x7a #x73 #x59 #xf6 #x7f
                     #x3d #x80 #x47 #x7d #x47 #x16 #xfe #x3e
                     #x1e #x23 #x7e #x44 #x6d #x7a #x88 #x3b
                     #xef #x44 #xa5 #x41 #xa8 #x52 #x5b #x7f
                     #xb6 #x71 #x25 #x3b #xdb #x0b #xad #x00
                     #xd4 #xd1 #xc6 #xf8 #x7c #x83 #x9d #x87
                     #xca #xf2 #xb8 #xbc #x11 #xf9 #x15 #xbc
                     #x6d #x88 #xa3 #x7a #x11 #x0b #x3e #xfd
                     #xdb #xf9 #x86 #x41 #xca #x00 #x93 #xfd
                     #x4e #x54 #xf7 #x0e #x5f #x5f #xc9 #xf3
                     #x84 #xa6 #x4f #xb2 #x4e #xa6 #xdc #x4f
                     #xea #xd2 #x73 #x21 #xb5 #x8d #xba #xd2
                     #x31 #x2b #xf5 #x60 #x7f #x8d #x29 #x2f
                     #xac #x77 #x66 #xf3 #x19 #xfa #xdc #x21
                     #x28 #xd1 #x29 #x41 #x57 #x5c #x00 #x6e
                     #xd0 #x14 #xf9 #xa8 #xc9 #xee #x25 #x89
                     #xe1 #x3f #x0c #xc8 #xb6 #x63 #x0c #xa6))

(check-equal? (nth-word (ke (AES (list  #x8e #x73 #xb0 #xf7
                                        #xda #x0e #x64 #x52 
                                        #xc8 #x10 #xf3 #x2b
                                        #x80 #x90 #x79 #xe5 
                                        #x62 #xf8 #xea #xd2 
                                        #x52 #x2c #x6b #x7b)))
                        29)
              (list #xd1 #x9d #xa4 #xe1))
(check-equal? (nth-word (ke (AES (list  #x8e #x73 #xb0 #xf7
                                        #xda #x0e #x64 #x52 
                                        #xc8 #x10 #xf3 #x2b
                                        #x80 #x90 #x79 #xe5 
                                        #x62 #xf8 #xea #xd2 
                                        #x52 #x2c #x6b #x7b)))
                        50)
              (list #x8e #xcc #x72 #x04))
(check-equal? (nth-word (ke (AES (list  #x8e #x73 #xb0 #xf7
                                        #xda #x0e #x64 #x52 
                                        #xc8 #x10 #xf3 #x2b
                                        #x80 #x90 #x79 #xe5 
                                        #x62 #xf8 #xea #xd2 
                                        #x52 #x2c #x6b #x7b)))
                        51)
              (list #x01 #x00 #x22 #x02))

(check-equal? (nth-word (ke (AES (list   #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe
                                         #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                                         #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7
                                         #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4)))
                        27)
              (list #xfa #xb8 #xb4 #x64))
(check-equal? (nth-word (ke (AES (list   #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe
                                         #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                                         #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7
                                         #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4))) 
                        32)
              (list #x68 #x00 #x7b #xac))
(check-equal? (nth-word (ke (AES (list   #x60 #x3d #xeb #x10 #x15 #xca #x71 #xbe
                                         #x2b #x73 #xae #xf0 #x85 #x7d #x77 #x81
                                         #x1f #x35 #x2c #x07 #x3b #x61 #x08 #xd7
                                         #x2d #x98 #x10 #xa3 #x09 #x14 #xdf #xf4))) 
                        59)
              (list #x70 #x6c #x63 #x1e))

;;****************************************************
;;******************************************************************************
;; AES Encryption Helpers
;;******************************************************************************
;;****************************************************


;;****************************************************
; AddRoundKey (ark) : AES box roundkeys -> box
;;****************************************************
; 5.1.4
; roundkeys : expects 4 32 bit integers
;; (could be revised to be a box as well...)
(define (ark data roundkey)
  (map bitwise-xor
       data
       roundkey))

;; byte-rc byte-list row column -> byte
(define (byte-rc bl r c)
  (list-ref bl (+ (* 4 c) r)))
;;****************************************************
; ShiftRows (sr) : box -> box
;;****************************************************
(define (sr data)
  (list (byte-rc data 0 0) (byte-rc data 1 1) (byte-rc data 2 2) (byte-rc data 3 3)
        (byte-rc data 0 1) (byte-rc data 1 2) (byte-rc data 2 3) (byte-rc data 3 0)
        (byte-rc data 0 2) (byte-rc data 1 3) (byte-rc data 2 0) (byte-rc data 3 1)
        (byte-rc data 0 3) (byte-rc data 1 0) (byte-rc data 2 1) (byte-rc data 3 2)))


(check-equal? (sr (list #x00 #x10 #x20 #x30
                        #x01 #x11 #x21 #x31
                        #x02 #x12 #x22 #x32
                        #x03 #x13 #x23 #x33))
              (list #x00 #x11 #x22 #x33
                    #x01 #x12 #x23 #x30
                    #x02 #x13 #x20 #x31
                    #x03 #x10 #x21 #x32))
(check-equal? (sr (list 0 1 2 3
                        4 5 6 7
                        8 9 10 11
                        12 13 14 15))
              (list 0 5 10 15
                    4 9 14 3
                    8 13 2 7
                    12 1 6 11))

;;****************************************************
;; mix-column (mc): list -> list
;;****************************************************
(define (mc-single col)
  (let ([a0 (list-ref col 0)]
        [a1 (list-ref col 1)]
        [a2 (list-ref col 2)]
        [a3 (list-ref col 3)])
    (list (GF+ (GF* 2 a0) (GF* 3 a1) (GF* 1 a2) (GF* 1 a3))
          (GF+ (GF* 1 a0) (GF* 2 a1) (GF* 3 a2) (GF* 1 a3))
          (GF+ (GF* 1 a0) (GF* 1 a1) (GF* 2 a2) (GF* 3 a3))
          (GF+ (GF* 3 a0) (GF* 1 a1) (GF* 1 a2) (GF* 2 a3)))))

(check-equal? (mc-single (list 219 19 83 69)) 
              (list 142 77 161 188))
(check-equal? (mc-single (list 242 10 34 92)) 
              (list 159 220 88 157))
(check-equal? (mc-single (list 1 1 1 1)) 
              (list 1 1 1 1))
(check-equal? (mc-single (list 198 198 198 198)) 
              (list 198 198 198 198))
(check-equal? (mc-single (list 212 212 212 213)) 
              (list 213 213 215 214))
(check-equal? (mc-single (list 45 38 49 76)) 
              (list 77 126 189 248))

; MixColumn : list-of-bytes -> list-of-bytes
; Assuming a 16 byte "box", as defined in AES spec
(define (mc lob)
  (append (mc-single (nth-word lob 0))
          (mc-single (nth-word lob 1))
          (mc-single (nth-word lob 2))
          (mc-single (nth-word lob 3))))

(check-equal? (mc (list 219 19 83 69
                        242 10 34 92
                        1   1  1  1
                        198 198 198 198))
              (list 142 77 161 188
                    159 220 88 157
                    1   1   1  1
                    198 198 198 198))


;;****************************************************
;;******************************************************************************
;; AES Encryption
;;******************************************************************************
;;****************************************************

; helper for cipher (the inner loop workhorse)
(define (aes-round Nb data round kexp)
  (ark (mc (sr (sb data)))
       (sublist kexp 
                (* 4 (* round Nb)) 
                (* 4 (* (add1 round) Nb)))))


;;****************************************************
; AES Encrypt (aes-encrypt) : AES bytearray  -> bytearray
;;****************************************************
(define (aes-encrypt aes input)
  (define kexp (ke aes))
  (define Nr (AES-Nr aes))
  (define state (ark input (sublist kexp 0 (* 4 Nb))))
  (ark (sr (sb (for/fold 
                   ([data state])
                 ([round (range 1 Nr)])
                 (aes-round Nb data round kexp))))
       (sublist kexp (* 4 (* Nr Nb)) (* 4 (* (add1 Nr) Nb)))))

; 128-bit example
(check-equal?
 (aes-encrypt
  (AES (0x "000102030405060708090a0b0c0d0e0f"))
  (0x "00112233445566778899aabbccddeeff"))
 (0x "69c4e0d86a7b0430d8cdb78070b4c55a"))

; 192-bit example
(check-equal?
 (aes-encrypt
  (AES (0x "000102030405060708090a0b0c0d0e0f1011121314151617"))
  (0x "00112233445566778899aabbccddeeff"))
 (0x "dda97ca4864cdfe06eaf70a0ec0d7191"))

; 256-bit example
(check-equal?
 (aes-encrypt 
  (AES (0x "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
  (0x "00112233445566778899aabbccddeeff"))
 (0x "8ea2b7ca516745bfeafc49904b496089"))

;;****************************************************
;;******************************************************************************
;; AES Decryption Helpers
;;******************************************************************************
;;****************************************************

; inv-sbox-sub : substitutes through inverse sbox (AES)
(define (inv-sbox-sub b)
  (matrix-ref 
   inv-sbox
   (bitwise-bit-field b 4 8)
   (bitwise-bit-field b 0 4)))

(check-equal? (inv-sbox-sub #x74) #xca)
(check-equal? (inv-sbox-sub 0) #x52)
(check-equal? (inv-sbox-sub #xe1) #xe0)

;;****************************************************
; InvSubBytes (sb) : list-of-bytes -> list-of-bytes
;;****************************************************
; takes list of bytes, performs sbox sub
(define (inv-sb lob)
  (map inv-sbox-sub lob))

(check-equal? (inv-sb (list #x13 #xee #x29))
              (list #x82 #x99 #x4c))


;;****************************************************
; InvShiftRows (rw) : list-of-bytes -> list-of-bytes
;;****************************************************
; takes list of bytes 4 long, and rotates them cyclicly
(define (inv-sr data)
  (list (byte-rc data 0 0)
        (byte-rc data 1 3)
        (byte-rc data 2 2)
        (byte-rc data 3 1)
        (byte-rc data 0 1)
        (byte-rc data 1 0)
        (byte-rc data 2 3)
        (byte-rc data 3 2)
        (byte-rc data 0 2)
        (byte-rc data 1 1)
        (byte-rc data 2 0)
        (byte-rc data 3 3)
        (byte-rc data 0 3)
        (byte-rc data 1 2)
        (byte-rc data 2 1)
        (byte-rc data 3 0)))

(check-equal? (inv-sr (sr (list #x00 #x10 #x20 #x30
                                #x01 #x11 #x21 #x31
                                #x02 #x12 #x22 #x32
                                #x03 #x13 #x23 #x33)))
              (list #x00 #x10 #x20 #x30
                    #x01 #x11 #x21 #x31
                    #x02 #x12 #x22 #x32
                    #x03 #x13 #x23 #x33))
(check-equal? (inv-sr (sr (list 0 1 2 3
                                4 5 6 7
                                8 9 10 11
                                12 13 14 15)))
              (list 0 1 2 3
                    4 5 6 7
                    8 9 10 11
                    12 13 14 15))

;;****************************************************
; InvMixColumns-sing (rw) : list-of-bytes -> list-of-bytes
;;****************************************************
(define (inv-mc-single col)
  (let ([a0 (list-ref col 0)]
        [a1 (list-ref col 1)]
        [a2 (list-ref col 2)]
        [a3 (list-ref col 3)])
    (list (GF+ (GF* #x0e a0) (GF* #x0b a1) (GF* #x0d a2) (GF* #x09 a3))
          (GF+ (GF* #x09 a0) (GF* #x0e a1) (GF* #x0b a2) (GF* #x0d a3))
          (GF+ (GF* #x0d a0) (GF* #x09 a1) (GF* #x0e a2) (GF* #x0b a3))
          (GF+ (GF* #x0b a0) (GF* #x0d a1) (GF* #x09 a2) (GF* #x0e a3)))))

(check-equal? (inv-mc-single (mc-single (list 219 19 83 69))) 
              (list 219 19 83 69))
(check-equal? (inv-mc-single (mc-single (list 242 10 34 92))) 
              (list 242 10 34 92))
(check-equal? (inv-mc-single (mc-single (list 1 1 1 1))) 
              (list 1 1 1 1))
(check-equal? (inv-mc-single (mc-single (list 198 198 198 198))) 
              (list 198 198 198 198))
(check-equal? (inv-mc-single (mc-single (list 212 212 212 213))) 
              (list 212 212 212 213))
(check-equal? (inv-mc-single (mc-single (list 45 38 49 76))) 
              (list 45 38 49 76))

; InvMixColumn : list-of-bytes -> list-of-bytes
; Assuming a 16 byte "box", as defined in AES spec
(define (inv-mc lob)
  (append (inv-mc-single (nth-word lob 0))
          (inv-mc-single (nth-word lob 1))
          (inv-mc-single (nth-word lob 2))
          (inv-mc-single (nth-word lob 3))))

(check-equal? (inv-mc (mc (list 219 19 83 69
                                242 10 34 92
                                1   1  1  1
                                198 198 198 198)))
              (list 219 19 83 69
                    242 10 34 92
                    1   1  1  1
                    198 198 198 198))

;;****************************************************
;;******************************************************************************
;; AES Decryption
;;******************************************************************************
;;****************************************************

; helper for cipher (the inner loop workhorse)
(define (inv-aes-round Nb data round kexp)
  (inv-mc (ark (inv-sb (inv-sr data))
               (sublist kexp 
                        (* 4 (* round Nb)) 
                        (* 4 (* (add1 round) Nb))))))

;;****************************************************
; AES Decrypt (aes-decrypt) : AES bytearray  -> bytearray
;;****************************************************
(define (aes-decrypt aes input)
  (define kexp (ke aes))
  (define Nr (AES-Nr aes))
  (define state (ark input (sublist kexp (* 4 Nr Nb) 
                                    (* 4 Nb (add1 Nr)))))
  (ark (inv-sb (inv-sr (for/fold 
                           ([data state])
                         ([round (reverse (range 1 Nr))])
                         (inv-aes-round Nb data round kexp))))
       (sublist kexp 0 (* 4 Nb))))

; 128-bit example
(check-equal?
 (aes-decrypt (AES (0x "000102030405060708090a0b0c0d0e0f"))
              (aes-encrypt
               (AES (0x "000102030405060708090a0b0c0d0e0f"))
               (0x "00112233445566778899aabbccddeeff")))
 (0x "00112233445566778899aabbccddeeff"))

; 192-bit example
(check-equal?
 (aes-decrypt (AES (0x "000102030405060708090a0b0c0d0e0f1011121314151617"))
              (aes-encrypt
               (AES (0x "000102030405060708090a0b0c0d0e0f1011121314151617"))
               (0x "00112233445566778899aabbccddeeff")))
 (0x "00112233445566778899aabbccddeeff"))

; 256-bit example
(check-equal?
 (aes-decrypt (AES (0x "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
              (aes-encrypt 
               (AES (0x "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
               (0x "00112233445566778899aabbccddeeff")))
 (0x "00112233445566778899aabbccddeeff"))