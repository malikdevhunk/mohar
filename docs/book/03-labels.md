# Labels

Every type carries two axes.

- Confidentiality: `public ⊑ secret`. A secret may flow into a secret slot. A secret may not flow into a public sink (`E105`).
- Integrity: `trusted ⊑ untrusted`. A trusted value may flow into an untrusted slot. An untrusted value may not flow into a trusted parameter (`E301`).

The default, and the label of a literal, is public and trusted. Write the qualifiers in front of the type:

```mohar
let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
let page: untrusted Text = inbox.read_text("invoice.txt");
```

The checker remembers where a label was introduced and points at it, the way a borrow checker points at the loan.

## Secrecy and branches

Branching on a secret is rejected outright in v0.1 (`E101`). So is using a secret as an index (`E102`), a loop bound (`E103`), or the operand of `/` or `%` or a secret shift amount (`E104`). The alternatives that stay in the language are constant-time selects and a comparison that reveals one bit on purpose:

```mohar
use std.ct;

fn tag_ok(expected: secret [u8; 32], given: [u8; 32]) -> bool {
    ct::verify_eq(expected, given)
}
```

`ct::verify_eq` is a trusted declassifier. It is allowed to return a public `bool`. The seal lists it.

This does not make the interpreter constant-time. It means a well-typed program has no secret-dependent branch for a later backend to lower. v0.2 may rewrite a pure secret `if` into a select. v0.1 does not.

## Integrity and the program counter

Branching on untrusted input taints the program counter. A trusted sink inside that branch is `E302`, even if the arguments are literals. The invoice example relies on this: the body of a mail may be untrusted, the recipient may not, and the decision to send may not be steered by the invoice.

```mohar
let to = Email::literal("accounts@acme.example");
mail.call(to, summary);          // summary is untrusted; to is a literal

// Email::parse(summary) is untrusted, and mail.send's recipient is trusted.
```

`agent::pick_from` is a trusted endorser. It returns one element of a list written in the program. The choice may be influenced by untrusted text. The value may not. Free-form endorsement is `endorse(value, "reason")`, which needs an `Endorse` capability and is copied into the seal. `declassify` is the confidentiality twin and needs `Declassify`.

Lengths are a size channel. `text.split_whitespace().len()` on untrusted text is a public `u64`. The limits section of the README says so. A secret collection's length stays secret, so printing it is still `E105`.
