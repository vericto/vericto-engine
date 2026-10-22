// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The CEL subset of Vericto policies: [`syntax`] (lexer and parser),
//! [`compile`] (the checker and the static bounds), [`eval`] (the
//! interpreter), over the values of [`value`].
//!
//! Why an in-house interpreter rather than the `cel` crate: the
//! implementation plan (Confluence, "Implementation plan: Business policy
//! rules, Phase 1") records the measurements. In short, `cel` 0.15.0
//! recompiles a `matches` pattern on every call and rebuilds its standard
//! library per context, has no checker and no cost budget, and brings an
//! ANTLR runtime and a time-zone database into the proxy. The grammar and
//! the semantics here are CEL's, and the crate is pinned as a test-only
//! oracle (`tests/policy_cel_conformance.rs`) for the subset.

pub(crate) mod compile;
#[cfg(test)]
mod conformance;
pub(crate) mod eval;
pub(crate) mod glob;
pub(crate) mod syntax;
pub(crate) mod time;
pub(crate) mod value;

use std::collections::BTreeMap;

pub(crate) use compile::{Diag, Field};
pub(crate) use eval::Activation;
pub(crate) use value::{Const, Fault, FaultKind};

/// A compiled expression.
#[derive(Debug, Clone)]
pub(crate) struct Program {
    pub(crate) compiled: compile::Compiled,
}

impl Program {
    pub(crate) fn compile(src: &str, vars: &BTreeMap<String, Const>) -> Result<Program, Vec<Diag>> {
        compile::compile(src, vars).map(|compiled| Program { compiled })
    }

    /// Evaluates to a bool, or the fault that kept it from one.
    pub(crate) fn eval_bool(&self, act: &Activation<'_>) -> Result<bool, Fault> {
        let v = eval::run(&self.compiled.node, act, self.compiled.slots)?;
        v.as_bool()
    }

    pub(crate) fn reads_stmt(&self) -> bool {
        self.compiled.info.reads_stmt
    }

    pub(crate) fn fields(&self) -> &std::collections::BTreeSet<Field> {
        &self.compiled.info.fields
    }

    pub(crate) fn warnings(&self) -> &[Diag] {
        &self.compiled.info.warnings
    }

    pub(crate) fn uses(&self, f: compile::Func) -> bool {
        fn walk(n: &compile::Node, f: compile::Func) -> bool {
            use compile::Node::*;
            match n {
                Call(g, args) => *g == f || args.iter().any(|a| walk(a, f)),
                Const(_) | Field(_) | Var(_) | HasField(_) => false,
                Select(a, _)
                | HasKey(a, _)
                | Not(a)
                | Neg(a)
                | Matches(a, _)
                | InWindow(a, _, _) => walk(a, f),
                Index(a, b) | And(a, b) | Or(a, b) | Bin(_, a, b) => walk(a, f) || walk(b, f),
                Cond(a, b, c) => walk(a, f) || walk(b, f) || walk(c, f),
                List(items) => items.iter().any(|a| walk(a, f)),
                Map(items) => items.iter().any(|(k, v)| walk(k, f) || walk(v, f)),
                Comp {
                    range, pred, body, ..
                } => {
                    walk(range, f)
                        || pred.as_deref().is_some_and(|p| walk(p, f))
                        || body.as_deref().is_some_and(|b| walk(b, f))
                }
            }
        }
        walk(&self.compiled.node, f)
    }
}
