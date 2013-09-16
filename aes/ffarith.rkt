#lang racket

(require rackunit)

(provide (all-defined-out))

;;****************************************************
;;******************************************************************************
;; Finite Field Math (used in AES spec)
;;******************************************************************************
;;****************************************************

;;****************************************************
;; GF+ : num ... -> num
;;****************************************************
(define-syntax GF+
  (syntax-rules ()
    [(GF+ a ...) 
     (bitwise-bit-field (bitwise-xor a ...) 
                        0
                        8)]))

(check-equal? (GF+ #x57 #x83) #xd4)

;;****************************************************
;; x* : num -> num
;;****************************************************
(define (x* num)
  (define n (bitwise-bit-field (* 2 num) 0 8))
  (if (bitwise-bit-set? num 7)
      (bitwise-xor n #x1b)
      n))


(check-equal? (x* #x57) #xae)
(check-equal? (x* (x* #x57)) #x47)
(check-equal? (x* (x* (x* #x57))) #x8e)

;;****************************************************
;; bitlist : num -> list num
;;****************************************************
; builds a list of which bits are 1's
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
;; apply* : (X -> X) num -> X
;;****************************************************
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
(define (GF* a b)
  (foldr (λ (x y) (GF+ x y)) 
         0 
         (map (λ (xpow) (apply* x* a xpow))
              (bitlist b 0))))

(check-equal? (GF* #x57 #x83) #xc1)