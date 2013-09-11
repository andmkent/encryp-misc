#lang racket

(require math/number-theory)
(require math/matrix)
(require racket/vector)
(require rackunit)

;;****************************************************
;;******************************************************************************
;; Finite Field Math
;;******************************************************************************
;;****************************************************

;;****************************************************
;; bitlist : num -> list num
;;****************************************************
;;
;;
(define-syntax GF+
  (syntax-rules ()
    [(GF+ a ...) (modulo (bitwise-xor a ...) 256)]))

(check-equal? (GF+ #x57 #x83) #xd4)

;;****************************************************
;; x* : num -> num
;;****************************************************
;;
;;
(define (x* num)
  (define n (modulo (* 2 num) 256))
  (if (zero? (bitwise-and 128 num))
      n
      (bitwise-xor n #x1b)))


(check-equal? (x* #x57) #xae)
(check-equal? (x* (x* #x57)) #x47)
(check-equal? (x* (x* (x* #x57))) #x8e)

;;****************************************************
;; bitlist : num -> list num
;;****************************************************
;;
;;
(define (bitlist bits ord)
  (cond
    [(zero? bits) empty]
    [(odd? bits) (cons ord 
                       (bitlist (quotient bits 2)
                                (add1 ord)))]
    [else
     (bitlist (quotient bits 2)
              (add1 ord))]))

(check-equal? (bitlist #x0 0) '())
(check-equal? (bitlist #x13 0) '(0 1 4))
(check-equal? (bitlist #xD4 0) '(2 4 6 7))

;;****************************************************
;; apply* : func X num -> X
;;****************************************************
;;
;;
(define (apply* f v i)
  (if (zero? i)
      v
      (apply* f (f v) (sub1 i))))

(check-equal? (apply* add1 0 0) 0)
(check-equal? (apply* add1 0 2) 2)
(check-equal? (apply* add1 0 3) 3)

;;****************************************************
;; GF* : num -> list num
;;****************************************************
;;
;;
(define (GF* a b)
  (foldr (λ (x y) (GF+ x y)) 0 (map (λ (xpow) (apply* x* a xpow))
                                    (bitlist b 0))))

(check-equal? (GF* #x57 #x83) #xc1)


;;****************************************************
;; mix-column : vector -> dec
;;****************************************************
(define (mix-column col)
  (let ([a0 (vector-ref col 0)]
        [a1 (vector-ref col 1)]
        [a2 (vector-ref col 2)]
        [a3 (vector-ref col 3)])
    (vector (GF+ (GF* 2 a0)
                 (GF* 3 a1)
                 (GF* 1 a2)
                 (GF* 1 a3))
            (GF+ (GF* 1 a0)
                 (GF* 2 a1)
                 (GF* 3 a2)
                 (GF* 1 a3))
            (GF+ (GF* 1 a0)
                 (GF* 1 a1)
                 (GF* 2 a2)
                 (GF* 3 a3))
            (GF+ (GF* 3 a0)
                 (GF* 1 a1)
                 (GF* 1 a2)
                 (GF* 2 a3)))))

(check-equal? (mix-column (vector 219 19 83 69)) 
              (vector 142 77 161 188))
(check-equal? (mix-column (vector 242 10 34 92)) 
              (vector 159 220 88 157))
(check-equal? (mix-column (vector 1 1 1 1)) 
              (vector 1 1 1 1))
(check-equal? (mix-column (vector 198 198 198 198)) 
              (vector 198 198 198 198))
(check-equal? (mix-column (vector 212 212 212 213)) 
              (vector 213 213 215 214))
(check-equal? (mix-column (vector 45 38 49 76)) 
              (vector 77 126 189 248))


;;****************************************************
;;******************************************************************************
;; AES Algorithm General
;;******************************************************************************
;;****************************************************

(struct AES (keylen)
  #:guard (λ (keylen type-name)
            (if (or (= 128 keylen)
                    (= 192 keylen)
                    (= 256 keylen))
                keylen
                (error type-name 
                       "invalid key length: ~e" 
                       keylen))))

(define (AES-Nb aes) 
  (if (AES? aes)
      4
      (error "non AES")))

(define (AES-Nk aes)
  (cond
    [(eq? 128 (AES-keylen aes)) 4]
    [(eq? 192 (AES-keylen aes)) 6]
    [(eq? 256 (AES-keylen aes)) 8]))

(define (AES-Nr aes)
  (cond
    [(eq? 4 (AES-Nk aes)) 10]
    [(eq? 6 (AES-Nk aes)) 12]
    [(eq? 8 (AES-Nk aes)) 14]))


(check-equal? (AES? (AES 128)) #t)
(check-equal? (AES? (AES 192)) #t)
(check-equal? (AES? (AES 256)) #t)
(check-exn exn:fail? (λ () (AES 1)))
(check-exn exn:fail? (λ () (AES 255)))

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


(define invsbox 
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
  #(#x00000000 
    #x01000000 #x02000000 #x04000000 #x08000000 
    #x10000000 #x20000000 #x40000000 #x80000000 
    #x1B000000 #x36000000 #x6C000000 #xD8000000 
    #xAB000000 #x4D000000 #x9A000000 #x2F000000 
    #x5E000000 #xBC000000 #x63000000 #xC6000000 
    #x97000000 #x35000000 #x6A000000 #xD4000000 
    #xB3000000 #x7D000000 #xFA000000 #xEF000000 
    #xC5000000 #x91000000 #x39000000 #x72000000 
    #xE4000000 #xD3000000 #xBD000000 #x61000000 
    #xC2000000 #x9F000000 #x25000000 #x4A000000 
    #x94000000 #x33000000 #x66000000 #xCC000000 
    #x83000000 #x1D000000 #x3A000000 #x74000000 
    #xE8000000 #xCB000000 #x8D000000))


; English description (5.1)
; 1) input copied into State array (conventions in Sec 3.4)
; 2) round key addition
; 3) State array transformed with round function (Nr times)
;   3a) Final round is different than previous rounds 
; 4) Final State now copied to output as described in Sec 3.4
;
;
;




;;****************************************************
;;******************************************************************************
;; AES Key Expansion
;;******************************************************************************
;;****************************************************



;;****************************************************
;;******************************************************************************
;; AES Cipher
;;******************************************************************************
;;****************************************************

;;****************************************************
;;******************************************************************************
;; AES Inverse Cipher
;;******************************************************************************
;;****************************************************





