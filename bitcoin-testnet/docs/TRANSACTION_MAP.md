# Figure 7 → Bitcoin transactions

## Setup phase — `tx_stp`

```
inputs:  [ client_funding UTXO of value ≥ (t+1)·x + fee ]
outputs: [ deposit_1 (x, 2-of-2 pk_A1∧pk_S1),
           …,
           deposit_{t+1} (x, 2-of-2 pk_A,t+1∧pk_S,t+1),
           optional change ]
```

Built by `SetupPlan::build_unsigned`.

## Auxiliary lock — `tx_aux,i`

```
inputs:  [ server coin ]
outputs: [ aux_i (ε′, P2WPKH pk_aux,i), optional change ]
```

`ε′ = max(paper ε, dust)`.

## Payment phase — `tx^j_pay,i`

```
inputs:  [ deposit_j UTXO , aux_i UTXO ]
outputs: [ server_receive_i (x + ε′ − fee) ]
witness / scriptSig:
  - for deposit input: signatures under pk_A,j and pk_S,j
      (paper: σ_A from adaptor Adapt(dk); σ_S from sk_S,j)
  - for aux input: signature under pk_aux,i
```

Built by `PaymentPlan::build_unsigned`.

## Pay-at-most-once

If server `i` already spent `aux_i` in `tx^{j}_pay,i`, any later
`tx^{j'}_pay,i` that reuses the same aux outpoint is rejected by
consensus / mempool. Simulated in `SimulatedLedger::apply`.
