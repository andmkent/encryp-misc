#lang racket

(require math/number-theory)
(require rackunit)

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
