#lang typed/racket

(require typed/rackunit)
(require (for-syntax racket/syntax))
(require (for-syntax syntax/parse))

(provide (all-defined-out))

;;****************************************************
;;******************************************************************************
;; Finite Field Math (used in AES spec)
;;******************************************************************************
;;****************************************************

;;****************************************************
;; GF+ Integer ... -> Integer
;;****************************************************
(: GF+ (Byte * -> Byte))
(define (GF+ . xs)
  (bitwise-bit-field
   (foldl (λ: ([x : Byte] [y : Byte]) 
            (bitwise-xor x y))
          0
          xs)
   0
   8))

(check-equal? (GF+ #x57 #x83) #xd4)

(define-syntax (build-static-vector stx)
  (syntax-parse 
   stx
   [(_ size-expr:expr fun-expr:expr)
    #`#,(syntax-local-eval 
         #`(cond 
             [(not (exact-nonnegative-integer? size-expr))
              (raise-syntax-error 'build-static-vector "invalid upper bound" size-expr)]
             [(not (procedure? fun-expr))
              (raise-syntax-error 'build-static-vector "invalid builder proc" fun-expr)]
             [else
              (build-vector size-expr fun-expr)]))]))

;;****************************************************
;; x*
;;****************************************************
(: x* (Byte -> Byte))
(define (x* b)
  (define: vec : (Vectorof Byte) 
    (build-static-vector 256 
                         (λ (i) (let ([n (bitwise-bit-field (* 2 i) 0 8)])
                                  (if (bitwise-bit-set? i 7)
                                      (bitwise-xor n #x1b)
                                      n)))))
  (vector-ref vec b))


(check-equal? (x* #x57) #xae)
(check-equal? (x* (x* #x57)) #x47)
(check-equal? (x* (x* (x* #x57))) #x8e)

;;****************************************************
;; num->bitlist
;;****************************************************
; builds a list of which bits are set to one 
; in the given number
(: num->bitlist (Integer -> (Listof Integer)))
(define (num->bitlist num)
  (: bitlist* (Integer Integer -> (Listof Integer)))
  (define (bitlist* bits ord) 
    (cond
      [(zero? bits) 
       empty]
      [(odd? bits) 
       (cons ord 
             (bitlist* (quotient bits 2)
                       (add1 ord)))]
      [else
       (bitlist* (quotient bits 2)
                 (add1 ord))]))
  (bitlist* num 0))

(check-equal? (num->bitlist #x0) '())
(check-equal? (num->bitlist #x13) '(0 1 4))
(check-equal? (num->bitlist #xD4) '(2 4 6 7))

;;****************************************************
;; repeat
;;****************************************************
(: repeat (All (X) ((X -> X) X Integer -> X)))
(define (repeat f x count)
  (if (zero? count)
      x
      (repeat f (f x) (sub1 count))))

(check-equal? (repeat add1 0 0) 0)
(check-equal? (repeat add1 0 2) 2)
(check-equal? (repeat add1 0 3) 3)

;;****************************************************
;; GF*
;;****************************************************
(: GF* (Byte Byte -> Byte))
(define (GF* a b)
  (foldl (λ: ([x : Byte] [y : Byte]) (GF+ x y)) 
         0 
         (map (λ: ([xpow : Integer]) (repeat x* a xpow))
              (num->bitlist b))))

(check-equal? (GF* #x57 #x83) #xc1)