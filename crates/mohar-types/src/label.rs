//! The two-axis label lattice.
//!
//! Confidentiality is `Public ⊑ Secret`. Integrity is `Trusted ⊑ Untrusted`.
//! A value labelled `(c, i)` may flow into a slot `(c', i')` only when
//! `c ⊑ c'` and `i ⊑ i'`. Joining two labels takes each axis's maximum:
//! the result is at least as secret and at least as untrusted as either input.

use std::cmp::Ordering;

/// Confidentiality. `Public` may flow into `Secret`; the other way is a leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Conf {
    Public,
    Secret,
}

/// Integrity. `Trusted` may flow into `Untrusted`; the other way is an endorsement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Integ {
    Trusted,
    Untrusted,
}

impl Conf {
    pub fn le(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Public, _) | (Self::Secret, Self::Secret)
        )
    }

    pub fn join(self, other: Self) -> Self {
        if self == Self::Secret || other == Self::Secret {
            Self::Secret
        } else {
            Self::Public
        }
    }
}

impl Integ {
    pub fn le(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Trusted, _) | (Self::Untrusted, Self::Untrusted)
        )
    }

    pub fn join(self, other: Self) -> Self {
        if self == Self::Untrusted || other == Self::Untrusted {
            Self::Untrusted
        } else {
            Self::Trusted
        }
    }
}

/// A pair of axes. The default label of a program literal is public and trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label {
    pub conf: Conf,
    pub integ: Integ,
}

impl Label {
    pub const PUBLIC_TRUSTED: Self = Self {
        conf: Conf::Public,
        integ: Integ::Trusted,
    };
    pub const SECRET: Self = Self {
        conf: Conf::Secret,
        integ: Integ::Trusted,
    };
    pub const UNTRUSTED: Self = Self {
        conf: Conf::Public,
        integ: Integ::Untrusted,
    };
    pub const SECRET_UNTRUSTED: Self = Self {
        conf: Conf::Secret,
        integ: Integ::Untrusted,
    };

    pub fn new(conf: Conf, integ: Integ) -> Self {
        Self { conf, integ }
    }

    /// `(c, i)` flows to `(c', i')` iff `c ⊑ c'` and `i ⊑ i'`.
    pub fn flows_to(self, other: Self) -> bool {
        self.conf.le(other.conf) && self.integ.le(other.integ)
    }

    /// Least upper bound. Join is componentwise max.
    pub fn join(self, other: Self) -> Self {
        Self {
            conf: self.conf.join(other.conf),
            integ: self.integ.join(other.integ),
        }
    }

    pub fn is_secret(self) -> bool {
        self.conf == Conf::Secret
    }

    pub fn is_untrusted(self) -> bool {
        self.integ == Integ::Untrusted
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::PUBLIC_TRUSTED
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.flows_to(*other), other.flows_to(*self)) {
            (true, true) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Less),
            (false, true) => Some(Ordering::Greater),
            (false, false) => None,
        }
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.conf, self.integ) {
            (Conf::Public, Integ::Trusted) => f.write_str("public trusted"),
            (Conf::Secret, Integ::Trusted) => f.write_str("secret"),
            (Conf::Public, Integ::Untrusted) => f.write_str("untrusted"),
            (Conf::Secret, Integ::Untrusted) => f.write_str("secret untrusted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn conf_s() -> impl Strategy<Value = Conf> {
        prop_oneof![Just(Conf::Public), Just(Conf::Secret)]
    }
    fn integ_s() -> impl Strategy<Value = Integ> {
        prop_oneof![Just(Integ::Trusted), Just(Integ::Untrusted)]
    }
    fn label_s() -> impl Strategy<Value = Label> {
        (conf_s(), integ_s()).prop_map(|(c, i)| Label::new(c, i))
    }

    proptest! {
        #[test]
        fn reflexive(l in label_s()) {
            prop_assert!(l.flows_to(l));
        }

        #[test]
        fn antisymmetric(a in label_s(), b in label_s()) {
            if a.flows_to(b) && b.flows_to(a) {
                prop_assert_eq!(a, b);
            }
        }

        #[test]
        fn transitive(a in label_s(), b in label_s(), c in label_s()) {
            if a.flows_to(b) && b.flows_to(c) {
                prop_assert!(a.flows_to(c));
            }
        }

        #[test]
        fn join_is_lub(a in label_s(), b in label_s(), c in label_s()) {
            let j = a.join(b);
            prop_assert!(a.flows_to(j));
            prop_assert!(b.flows_to(j));
            if a.flows_to(c) && b.flows_to(c) {
                prop_assert!(j.flows_to(c));
            }
        }

        #[test]
        fn join_idempotent_commutative(a in label_s(), b in label_s()) {
            prop_assert_eq!(a.join(a), a);
            prop_assert_eq!(a.join(b), b.join(a));
            prop_assert_eq!(a.join(b).join(b), a.join(b));
        }
    }

    #[test]
    fn secret_does_not_flow_to_public() {
        assert!(!Label::SECRET.flows_to(Label::PUBLIC_TRUSTED));
        assert!(Label::PUBLIC_TRUSTED.flows_to(Label::SECRET));
    }

    #[test]
    fn untrusted_does_not_flow_to_trusted() {
        assert!(!Label::UNTRUSTED.flows_to(Label::PUBLIC_TRUSTED));
        assert!(Label::PUBLIC_TRUSTED.flows_to(Label::UNTRUSTED));
    }

    #[test]
    fn axes_are_independent() {
        // A secret trusted value is not an integrity problem, and an
        // untrusted public value is not a confidentiality problem.
        assert!(Label::SECRET.flows_to(Label::SECRET_UNTRUSTED));
        assert!(!Label::SECRET_UNTRUSTED.flows_to(Label::SECRET));
        assert!(!Label::UNTRUSTED.flows_to(Label::SECRET));
    }
}
