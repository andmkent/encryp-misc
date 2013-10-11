#lang racket
(require rackunit)
(require math/number-theory)
(require math/base)

; ********************************************************************
; moduler exponentiation
; b = base
; p = power
; m = modulo
(define (mod^ b p m)
  (let loop ([result 1] [pow p] [base b])
    (if (> pow 0)
        (loop (if (odd? pow)
                  (modulo (* result base) m)
                  result)
              (arithmetic-shift pow -1)
              (modulo (sqr base) m))
        result)))

(define a1 (random-natural 10000))
(define b1 (random-natural 10000))
(define c1 (random-natural 10000))
(define a2 (random-natural 10000))
(define b2 (random-natural 10000))
(define c2 (random-natural 10000))
(define a3 (random-natural 10000))
(define b3 (random-natural 10000))
(define c3 (random-natural 10000))

(check-equal? (mod^ a1 a2 a3) (modulo (expt a1 a2) a3))
(check-equal? (mod^ b1 b2 b3) (modulo (expt b1 b2) b3))
(check-equal? (mod^ c1 c2 c3) (modulo (expt c1 c2) c3))

; ********************************************************************
; find a prime greater than num
(define (find-prime> num)
  (if (prime? num)
      num
      (find-prime> (add1 num))))

; ********************************************************************
; gcd
(define (gcd* a b)
  (if (zero? b)
      a
      (gcd* b (modulo a b))))

(check-equal? (gcd 2 67) (gcd* 2 67))
(check-equal? (gcd 76 238) (gcd* 76 238))
(check-equal? (gcd 324 1984) (gcd* 324 1984))

; ********************************************************************
; Calculating d

; Extended Euclidean algorithm
(define (egcd a b)
  (if (zero? b)
      '(1 . 0)
  (let* ([q (quotient a b)]
        [r (remainder a b)]
        [acc (egcd b r)]
        [s (car acc)]
        [t (cdr acc)])
    (cons t (- s (* q t))))))

; extracts correct d from extended-eucl
(define (calc-d e phin)
  (let ([d (car (egcd e phin))])
    (cond
      [(< 0 d phin)
       d]
      [(< d 0)
       (+ phin d)]
      [else
       (error 'calc-d "invalid egcd result ~a\n" d)])))

(check-equal? (calc-d 5 72) 29)
(check-equal? (calc-d 17 3120) 2753)
(check-equal? (calc-d 17 43) 38)


; ********************************************************************
; Some big picture tests
(define range-delta (- (expt 2 512) (expt 2 511)))
(define p (find-prime> (+ (random-natural range-delta) (expt 2 511))))
(define q (find-prime> (add1 p)))
(check-equal? (and (prime? p) (prime? q) (not (= p q))) #t)
(check-equal? (< (expt 2 511 ) p (expt 2 512)) #t)
(check-equal? (< (expt 2 511 ) q (expt 2 512)) #t)
(define n (* p q))
(define e 65537)
(check-equal? (gcd* n e) 1)
(define phin (* (sub1 p) (sub1 q)))
(check-equal?  (gcd* e phin) 1)
(define d (calc-d e phin))
(check-equal? (modulo (* d e) phin) 1)

(define t1 (random-natural n))
(define t2 (random-natural n))
(define t3 (random-natural n))
(check-equal? (mod^ (mod^ t1 e n) d n) t1)
(check-equal? (mod^ (mod^ t2 e n) d n) t2)
(check-equal? (mod^ (mod^ t3 e n) d n) t3)

; ********************************************************************
; Encryption w/ randomly generated values for this run(above)
(define (rsa-encr m)
  (if (< m n)
      (mod^ m e n)
      #f))
; ********************************************************************
; Decryption w/ randomly generated values for this run(above)
(define (rsa-decr m)
  (if (< m n)
      (mod^ m d n)
      #f))

; print out cryptographic values
(printf "p: ~a \n" p)
(printf "q: ~a \n" q)
(printf "n: ~a \n" n)
(printf "phi(n): ~a \n" phin)
(printf "e: ~a \n" e)
(printf "d: ~a \n" d)