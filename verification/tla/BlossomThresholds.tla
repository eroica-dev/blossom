---- MODULE BlossomThresholds ----
EXTENDS Naturals, TLC

CONSTANT
  \* @type: Int;
  MaxN
VARIABLE
  \* @type: Int;
  tick

SupermajorityCount(n) == n - (n \div 3)
ByzantineFaultBound(n) == (n - 1) \div 3
MaxLivenessOmissions(n) == n - SupermajorityCount(n)
MinSupermajorityIntersection(n) == (2 * SupermajorityCount(n)) - n

Init == tick = 0
Next == tick' = tick

HonestOverlapBoundary ==
  \A n \in 1..MaxN:
    MinSupermajorityIntersection(n) > ByzantineFaultBound(n)

UnsafeBoundary ==
  \A n \in 1..MaxN:
    (2 * (SupermajorityCount(n) - 1)) - n <= ByzantineFaultBound(n)

SixNodeThresholds ==
  /\ SupermajorityCount(6) = 4
  /\ MaxLivenessOmissions(6) = 2
  /\ ByzantineFaultBound(6) = 1
  /\ MinSupermajorityIntersection(6) = 2

====
