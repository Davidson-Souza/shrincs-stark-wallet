import Std

namespace ShrincsStarkWallet

abbrev SignerId := Nat
abbrev Digest := Array UInt8

structure Share where
  signer : SignerId
  deriving DecidableEq

/-- The executable quorum check counts distinct share records, never raw inputs. -/
def quorumAccepted (threshold : Nat) (shares : List Share) : Prop :=
  threshold ≤ shares.length ∧ (shares.map Share.signer).Nodup

theorem accepted_meets_threshold
    {threshold : Nat} {shares : List Share}
    (accepted : quorumAccepted threshold shares) :
    threshold ≤ shares.length :=
  accepted.1

theorem accepted_has_distinct_signers
    {threshold : Nat} {shares : List Share}
    (accepted : quorumAccepted threshold shares) :
    (shares.map Share.signer).Nodup :=
  accepted.2

theorem duplicate_pair_rejected (threshold signer : Nat) :
    ¬ quorumAccepted threshold [{ signer := signer }, { signer := signer }] := by
  intro accepted
  simpa using accepted.2

structure Policy where
  threshold : Nat
  members : List SignerId

structure SignedShare where
  signer : SignerId
  signature : Array UInt8

/-- The relation encoded by a threshold-signature proof circuit. -/
def quorumRelation
    (policy : Policy)
    (requestDigest : Digest)
    (validSignature : SignedShare → Digest → Prop)
    (shares : List SignedShare) : Prop :=
  policy.threshold ≤ shares.length ∧
    (shares.map SignedShare.signer).Nodup ∧
    ∀ share ∈ shares,
      share.signer ∈ policy.members ∧ validSignature share requestDigest

/--
The cryptographic boundary: a STARK verifier is sound for the quorum relation.
Concrete soundness depends on the implemented AIR, Fiat–Shamir hash, and FRI.
-/
structure SoundQuorumProof
    (policy : Policy)
    (requestDigest : Digest)
    (validSignature : SignedShare → Digest → Prop) where
  ProofType : Type
  verify : ProofType → Bool
  sound :
    ∀ proof,
      verify proof = true →
        ∃ shares, quorumRelation policy requestDigest validSignature shares

theorem onchain_acceptance_implies_distinct_valid_quorum
    {policy : Policy}
    {requestDigest : Digest}
    {validSignature : SignedShare → Digest → Prop}
    (system : SoundQuorumProof policy requestDigest validSignature)
    (proof : system.ProofType)
    (accepted : system.verify proof = true) :
    ∃ shares : List SignedShare,
      policy.threshold ≤ shares.length ∧
        (shares.map SignedShare.signer).Nodup ∧
        ∀ share ∈ shares,
          share.signer ∈ policy.members ∧ validSignature share requestDigest :=
  system.sound proof accepted

theorem onchain_acceptance_meets_threshold
    {policy : Policy}
    {requestDigest : Digest}
    {validSignature : SignedShare → Digest → Prop}
    (system : SoundQuorumProof policy requestDigest validSignature)
    (proof : system.ProofType)
    (accepted : system.verify proof = true) :
    ∃ shares : List SignedShare, policy.threshold ≤ shares.length := by
  obtain ⟨shares, relation⟩ := system.sound proof accepted
  exact ⟨shares, relation.1⟩

structure SignState where
  index : Nat
  valid : Bool
  deriving DecidableEq

/-- A successful stateful SHRINCS signature consumes one of `limit` indices. -/
def consumeState (limit : Nat) (state : SignState) : Option SignState :=
  if state.valid && state.index < limit
  then some { index := state.index + 1, valid := true }
  else none

theorem successful_stateful_sign_strictly_advances
    {limit : Nat} {before after : SignState}
    (success : consumeState limit before = some after) :
    after.index = before.index + 1 := by
  unfold consumeState at success
  split at success
  · cases success
    rfl
  · contradiction

theorem invalid_state_cannot_sign
    {limit : Nat} {state : SignState}
    (invalid : state.valid = false) :
    consumeState limit state = none := by
  simp [consumeState, invalid]

theorem exhausted_state_cannot_sign
    {limit : Nat} {state : SignState}
    (exhausted : limit ≤ state.index) :
    consumeState limit state = none := by
  simp [consumeState, Nat.not_lt.mpr exhausted]

structure RequestPreimage where
  policyId : Digest
  network : Array UInt8
  unsignedTransactionHash : Digest
  inputIndex : Nat
  transactionSighash : Digest
  deriving DecidableEq

structure IdealHash where
  hash : RequestPreimage → Digest
  collisionFree : Function.Injective hash

def authorizationDigest (hash : IdealHash) (request : RequestPreimage) : Digest :=
  hash.hash request

theorem authorization_is_bound_to_complete_request
    (hash : IdealHash) {left right : RequestPreimage}
    (sameDigest : authorizationDigest hash left = authorizationDigest hash right) :
    left.policyId = right.policyId ∧
      left.network = right.network ∧
      left.unsignedTransactionHash = right.unsignedTransactionHash ∧
      left.inputIndex = right.inputIndex ∧
      left.transactionSighash = right.transactionSighash := by
  have sameRequest : left = right := hash.collisionFree sameDigest
  cases sameRequest
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- Prime used by the imported STARK-101 verifier. -/
def starkPrime : Nat := 3221225473

def addMod (left right : Nat) : Nat := (left + right) % starkPrime

def mulMod (left right : Nat) : Nat := (left * right) % starkPrime

theorem addMod_is_canonical (left right : Nat) :
    addMod left right < starkPrime := by
  exact Nat.mod_lt _ (by decide)

theorem mulMod_is_canonical (left right : Nat) :
    mulMod left right < starkPrime := by
  exact Nat.mod_lt _ (by decide)

/-- Fibonacci-square AIR transition checked by the Simplicity verifier. -/
def fibSquareStep (current next following : Nat) : Prop :=
  following % starkPrime = addMod (mulMod current current) (mulMod next next)

theorem honest_fib_square_step (current next : Nat) :
    fibSquareStep current next
      (addMod (mulMod current current) (mulMod next next)) := by
  unfold fibSquareStep
  exact Nat.mod_eq_of_lt (addMod_is_canonical _ _)

end ShrincsStarkWallet
