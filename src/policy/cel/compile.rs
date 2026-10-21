// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The checker: types an expression against the fixed policy schema
//! (design §4.2), enforces the static bounds (§4.7) and lowers it to the
//! [`Node`] tree the interpreter runs.
//!
//! It is the only source of truth for save-time validation: the dashboard
//! and `PUT /rules/custom` reach it through the eval sidecar, so there is no
//! second implementation to drift. Everything it refuses is refused with a
//! position: unknown identifiers and fields (with a suggestion), functions
//! outside the allowed subset, fields of later phases, type errors the
//! schema makes certain, non-constant `matches`/`timestamp`/`duration`/
//! `in_window` arguments, and expressions over the bounds.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::syntax::{self, BinOp, Expr, ExprKind, Lit, Macro, SyntaxError, UnOp};
use super::time::{self, TzSpec, WindowSpec};
use super::value::Const;
use crate::policy::context::HostMode;

/// Longest expression source (design §4.7).
pub const MAX_EXPR_BYTES: usize = 2048;
/// Most syntax-tree nodes in one expression.
pub const MAX_EXPR_NODES: usize = 256;
/// Deepest nesting of comprehensions (`all`, `exists`, `map`, …).
pub const MAX_COMPREHENSION_NESTING: usize = 2;
/// Longest `matches` pattern, in bytes.
pub const MAX_REGEX_BYTES: usize = 256;
/// Largest estimated cost of one expression: an upper bound on the work of
/// any evaluation, from the bounded fact lists and the comprehension
/// nesting (one unit is about one node visit).
pub const MAX_COST: u64 = 100_000;
/// Compiled-program memory limit for a `matches` pattern (regex crate).
const REGEX_SIZE_LIMIT: usize = 1 << 16;

/// The type of an expression, as far as the schema says.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ty {
    Bool,
    Int,
    Uint,
    Double,
    String,
    Null,
    Timestamp,
    Duration,
    List(Box<Ty>),
    Map(Box<Ty>, Box<Ty>),
    Dyn,
    /// A root object (`principal`, `stmt`, …): only for selection.
    Obj(Root),
}

impl Ty {
    fn name(&self) -> String {
        match self {
            Ty::Bool => "bool".into(),
            Ty::Int => "int".into(),
            Ty::Uint => "uint".into(),
            Ty::Double => "double".into(),
            Ty::String => "string".into(),
            Ty::Null => "null".into(),
            Ty::Timestamp => "timestamp".into(),
            Ty::Duration => "duration".into(),
            Ty::List(t) => format!("list({})", t.name()),
            Ty::Map(k, v) => format!("map({}, {})", k.name(), v.name()),
            Ty::Dyn => "dyn".into(),
            Ty::Obj(r) => r.name().into(),
        }
    }

    fn numeric(&self) -> bool {
        matches!(self, Ty::Int | Ty::Uint | Ty::Double)
    }

    /// Whether values of the two types can ever be equal.
    fn comparable_eq(&self, other: &Ty) -> bool {
        match (self, other) {
            (Ty::Dyn, _) | (_, Ty::Dyn) | (Ty::Null, _) | (_, Ty::Null) => true,
            (a, b) if a.numeric() && b.numeric() => true,
            (Ty::List(a), Ty::List(b)) => a.comparable_eq(b),
            (Ty::Map(ak, av), Ty::Map(bk, bv)) => ak.comparable_eq(bk) && av.comparable_eq(bv),
            (Ty::Obj(_), _) | (_, Ty::Obj(_)) => false,
            (a, b) => a == b,
        }
    }

    fn orderable_with(&self, other: &Ty) -> bool {
        match (self, other) {
            (Ty::Dyn, b) | (b, Ty::Dyn) => {
                !matches!(b, Ty::List(_) | Ty::Map(..) | Ty::Obj(_) | Ty::Null)
            }
            (a, b) if a.numeric() && b.numeric() => true,
            (Ty::String, Ty::String)
            | (Ty::Bool, Ty::Bool)
            | (Ty::Timestamp, Ty::Timestamp)
            | (Ty::Duration, Ty::Duration) => true,
            _ => false,
        }
    }

    fn join(a: Ty, b: Ty) -> Ty {
        if a == b {
            a
        } else if a == Ty::Null {
            b
        } else if b == Ty::Null {
            a
        } else {
            Ty::Dyn
        }
    }

    fn elem(&self) -> Option<Ty> {
        match self {
            Ty::List(t) => Some((**t).clone()),
            Ty::Map(k, _) => Some((**k).clone()),
            Ty::Dyn => Some(Ty::Dyn),
            _ => None,
        }
    }
}

fn of_const(c: &Const) -> Ty {
    match c {
        Const::Null => Ty::Null,
        Const::Bool(_) => Ty::Bool,
        Const::Int(_) => Ty::Int,
        Const::Uint(_) => Ty::Uint,
        Const::Double(_) => Ty::Double,
        Const::Str(_) => Ty::String,
        Const::Timestamp(_) => Ty::Timestamp,
        Const::Duration(_) => Ty::Duration,
        Const::List(items) => {
            let t = items
                .iter()
                .map(of_const)
                .reduce(Ty::join)
                .unwrap_or(Ty::Dyn);
            Ty::List(Box::new(t))
        }
        Const::Map(m) => {
            let t = m.values().map(of_const).reduce(Ty::join).unwrap_or(Ty::Dyn);
            Ty::Map(Box::new(Ty::String), Box::new(t))
        }
    }
}

/// The root objects of the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Root {
    Principal,
    Stmt,
    Db,
    Time,
    Session,
    Ticket,
    Vars,
}

impl Root {
    fn name(self) -> &'static str {
        match self {
            Root::Principal => "principal",
            Root::Stmt => "stmt",
            Root::Db => "db",
            Root::Time => "time",
            Root::Session => "session",
            Root::Ticket => "ticket",
            Root::Vars => "vars",
        }
    }
}

/// A leaf field of the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Field {
    PrincipalType,
    PrincipalId,
    PrincipalOwner,
    PrincipalTrust,
    PrincipalVia,
    PrincipalAttrs,
    PrincipalGroups,
    PrincipalEndUser,
    StmtOp,
    StmtKind,
    StmtTables,
    StmtTablesWritten,
    StmtColumnsRead,
    StmtColumnsWritten,
    StmtFunctions,
    StmtHasWhere,
    StmtWhereAlwaysTrue,
    StmtLimit,
    StmtHasReturning,
    StmtInsertRows,
    StmtTruncated,
    DbId,
    DbName,
    DbEnv,
    DbTags,
    DbDialect,
    TimeNow,
    TimeHour,
    TimeMinute,
    TimeWeekday,
    TimeDate,
    TimeTz,
    SessionTenant,
    SessionApplicationName,
    SessionClientIp,
    SessionListener,
    TicketId,
    TicketSource,
    TicketVerified,
}

/// Where a field can be known (design §4.2 table, Phase 1 columns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Avail {
    /// From the SQL or the host, in every mode.
    Static,
    /// Declared by the caller in these modes; absent in the others.
    Declared(&'static [HostMode]),
    /// Known in these modes only (the proxy's session signals).
    Only(&'static [HostMode]),
    /// Static except in CI, where the caller declares it (`--database`).
    DeclaredInCi,
}

const PROXY: &[HostMode] = &[HostMode::Proxy];
const PROXY_API: &[HostMode] = &[HostMode::Proxy, HostMode::RuntimeApi];
const API: &[HostMode] = &[HostMode::RuntimeApi];
const ALL: &[HostMode] = &[
    HostMode::Proxy,
    HostMode::RuntimeApi,
    HostMode::Mcp,
    HostMode::Ci,
];

struct FieldDef {
    root: Root,
    name: &'static str,
    field: Field,
    ty: fn() -> Ty,
    avail: Avail,
}

fn list_str() -> Ty {
    Ty::List(Box::new(Ty::String))
}
fn map_str() -> Ty {
    Ty::Map(Box::new(Ty::String), Box::new(Ty::String))
}

macro_rules! fd {
    ($root:ident, $name:literal, $field:ident, $ty:expr, $avail:expr) => {
        FieldDef {
            root: Root::$root,
            name: $name,
            field: Field::$field,
            ty: $ty,
            avail: $avail,
        }
    };
}

const FIELDS: &[FieldDef] = &[
    fd!(
        Principal,
        "type",
        PrincipalType,
        || Ty::String,
        Avail::Static
    ),
    fd!(Principal, "id", PrincipalId, || Ty::String, Avail::Static),
    fd!(
        Principal,
        "owner",
        PrincipalOwner,
        || Ty::String,
        Avail::Static
    ),
    fd!(
        Principal,
        "trust",
        PrincipalTrust,
        || Ty::Int,
        Avail::Static
    ),
    fd!(Principal, "via", PrincipalVia, || Ty::String, Avail::Static),
    fd!(Principal, "attrs", PrincipalAttrs, map_str, Avail::Static),
    fd!(
        Principal,
        "groups",
        PrincipalGroups,
        list_str,
        Avail::Static
    ),
    fd!(
        Principal,
        "end_user",
        PrincipalEndUser,
        map_str,
        Avail::Declared(API)
    ),
    fd!(Stmt, "op", StmtOp, || Ty::String, Avail::Static),
    fd!(Stmt, "kind", StmtKind, || Ty::String, Avail::Static),
    fd!(Stmt, "tables", StmtTables, list_str, Avail::Static),
    fd!(
        Stmt,
        "tables_written",
        StmtTablesWritten,
        list_str,
        Avail::Static
    ),
    fd!(
        Stmt,
        "columns_read",
        StmtColumnsRead,
        list_str,
        Avail::Static
    ),
    fd!(
        Stmt,
        "columns_written",
        StmtColumnsWritten,
        list_str,
        Avail::Static
    ),
    fd!(Stmt, "functions", StmtFunctions, list_str, Avail::Static),
    fd!(Stmt, "has_where", StmtHasWhere, || Ty::Bool, Avail::Static),
    fd!(
        Stmt,
        "where_always_true",
        StmtWhereAlwaysTrue,
        || Ty::Bool,
        Avail::Static
    ),
    fd!(Stmt, "limit", StmtLimit, || Ty::Int, Avail::Static),
    fd!(
        Stmt,
        "has_returning",
        StmtHasReturning,
        || Ty::Bool,
        Avail::Static
    ),
    fd!(
        Stmt,
        "insert_rows",
        StmtInsertRows,
        || Ty::Int,
        Avail::Static
    ),
    fd!(Stmt, "truncated", StmtTruncated, || Ty::Bool, Avail::Static),
    fd!(Db, "id", DbId, || Ty::String, Avail::DeclaredInCi),
    fd!(Db, "name", DbName, || Ty::String, Avail::DeclaredInCi),
    fd!(Db, "env", DbEnv, || Ty::String, Avail::DeclaredInCi),
    fd!(Db, "tags", DbTags, list_str, Avail::DeclaredInCi),
    fd!(Db, "dialect", DbDialect, || Ty::String, Avail::Static),
    fd!(Time, "now", TimeNow, || Ty::Timestamp, Avail::Static),
    fd!(Time, "hour", TimeHour, || Ty::Int, Avail::Static),
    fd!(Time, "minute", TimeMinute, || Ty::Int, Avail::Static),
    fd!(Time, "weekday", TimeWeekday, || Ty::Int, Avail::Static),
    fd!(Time, "date", TimeDate, || Ty::String, Avail::Static),
    fd!(Time, "tz", TimeTz, || Ty::String, Avail::Static),
    fd!(
        Session,
        "tenant",
        SessionTenant,
        || Ty::String,
        Avail::Declared(PROXY_API)
    ),
    fd!(
        Session,
        "application_name",
        SessionApplicationName,
        || Ty::String,
        Avail::Only(PROXY)
    ),
    fd!(
        Session,
        "client_ip",
        SessionClientIp,
        || Ty::String,
        Avail::Only(PROXY)
    ),
    fd!(
        Session,
        "listener",
        SessionListener,
        || Ty::String,
        Avail::Only(PROXY)
    ),
    fd!(Ticket, "id", TicketId, || Ty::String, Avail::Declared(ALL)),
    fd!(
        Ticket,
        "source",
        TicketSource,
        || Ty::String,
        Avail::Declared(ALL)
    ),
    fd!(
        Ticket,
        "verified",
        TicketVerified,
        || Ty::Bool,
        Avail::Declared(ALL)
    ),
];

/// Fields and roots of later phases, refused with the phase that brings them.
const LATER: &[(&str, &str)] = &[
    ("approval", "approval grants are Phase 3"),
    ("params", "bind values are Phase 2"),
    ("result", "row counts are Phase 2/3"),
    ("usage", "budgets are Phase 3"),
    (
        "stmt.columns_projected",
        "not available in this engine version",
    ),
    ("stmt.where_columns", "not available in this engine version"),
    ("session.in_transaction", "the transaction state is Phase 2"),
];

impl Field {
    pub(crate) fn path(self) -> String {
        let d = FIELDS
            .iter()
            .find(|d| d.field == self)
            .expect("every field is defined");
        format!("{}.{}", d.root.name(), d.name)
    }

    fn def(self) -> &'static FieldDef {
        FIELDS
            .iter()
            .find(|d| d.field == self)
            .expect("every field is defined")
    }

    /// Whether the field reads the statement facts.
    pub(crate) fn is_stmt(self) -> bool {
        self.def().root == Root::Stmt
    }
}

/// The comprehension-free helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Func {
    Size,
    Int,
    Uint,
    Double,
    String,
    Bool,
    Dyn,
    Contains,
    StartsWith,
    EndsWith,
    Glob,
    CidrContains,
    StmtValues,
    StmtFilterValues,
    StmtHasFilter,
    StmtLowerBound,
    StmtUpperBound,
    StmtReads,
    StmtWrites,
    StmtTouches,
}

/// The lowered expression the interpreter runs.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    Const(Const),
    Field(Field),
    /// A comprehension variable, by slot.
    Var(usize),
    /// `map.key` on a map value.
    Select(Box<Node>, String),
    /// `has(principal.owner)`: the field is present.
    HasField(Field),
    /// `has(map.key)`.
    HasKey(Box<Node>, String),
    Index(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Neg(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Bin(BinOp, Box<Node>, Box<Node>),
    Cond(Box<Node>, Box<Node>, Box<Node>),
    List(Vec<Node>),
    Map(Vec<(Node, Node)>),
    Call(Func, Vec<Node>),
    Matches(Box<Node>, Arc<regex::Regex>),
    InWindow(Box<Node>, Arc<WindowSpec>, TzSpec),
    Comp {
        mac: Macro,
        range: Box<Node>,
        slot: usize,
        pred: Option<Box<Node>>,
        body: Option<Box<Node>>,
    },
}

/// A checker finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub offset: usize,
    pub message: String,
}

/// What the checker learned about an expression.
#[derive(Debug, Clone, Default)]
pub(crate) struct Info {
    pub(crate) fields: std::collections::BTreeSet<Field>,
    pub(crate) reads_stmt: bool,
    pub(crate) warnings: Vec<Diag>,
    pub(crate) cost: u64,
    /// `in_window` with a named zone: decided only when it is the host's.
    pub(crate) named_zones: Vec<String>,
}

/// A checked, lowered expression.
#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    pub(crate) node: Node,
    pub(crate) info: Info,
    pub(crate) slots: usize,
    pub(crate) ty: Ty,
}

pub(crate) fn compile(src: &str, vars: &BTreeMap<String, Const>) -> Result<Compiled, Vec<Diag>> {
    if src.len() > MAX_EXPR_BYTES {
        return Err(vec![Diag {
            offset: 0,
            message: format!(
                "expression is {} bytes; the limit is {MAX_EXPR_BYTES}",
                src.len()
            ),
        }]);
    }
    let ast = syntax::parse(src).map_err(|e: SyntaxError| {
        vec![Diag {
            offset: e.offset,
            message: e.message,
        }]
    })?;
    let nodes = ast.node_count();
    if nodes > MAX_EXPR_NODES {
        return Err(vec![Diag {
            offset: 0,
            message: format!("expression has {nodes} nodes; the limit is {MAX_EXPR_NODES}"),
        }]);
    }
    let mut c = Checker {
        vars,
        scopes: Vec::new(),
        slots: 0,
        nesting: 0,
        errors: Vec::new(),
        info: Info::default(),
    };
    let (node, ty, cost) = c.check(&ast);
    c.not_obj(&ty, ast.pos);
    if !c.errors.is_empty() {
        return Err(c.errors);
    }
    if cost > MAX_COST {
        return Err(vec![Diag {
            offset: 0,
            message: format!(
                "the estimated worst-case cost of this expression is {cost}; the limit is {MAX_COST} \
                 (nested comprehensions over statement facts are the usual cause)"
            ),
        }]);
    }
    let mut info = c.info;
    info.cost = cost;
    info.reads_stmt = info.reads_stmt || info.fields.iter().any(|f| f.is_stmt());
    Ok(Compiled {
        node,
        info,
        slots: c.slots,
        ty,
    })
}

struct Checker<'v> {
    vars: &'v BTreeMap<String, Const>,
    /// Comprehension variables in scope: (name, slot, type, size bound).
    scopes: Vec<(String, usize, Ty)>,
    slots: usize,
    nesting: usize,
    errors: Vec<Diag>,
    info: Info,
}

/// The bound of a list a comprehension may range over.
const FACT_LIST_BOUND: u64 = crate::policy::facts::MAX_FACTS as u64;
const CTX_LIST_BOUND: u64 = 256;

fn similar<'a>(name: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    candidates
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, c)| *d <= 2 && *d < c.len())
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            cur[j] = (prev[j] + 1)
                .min(cur[j - 1] + 1)
                .min(prev[j - 1] + usize::from(a[i - 1] != b[j - 1]));
        }
        prev = cur;
    }
    prev[b.len()]
}

impl<'v> Checker<'v> {
    fn error(&mut self, offset: usize, message: impl Into<String>) {
        self.errors.push(Diag {
            offset,
            message: message.into(),
        });
    }

    fn warn(&mut self, offset: usize, message: impl Into<String>) {
        self.info.warnings.push(Diag {
            offset,
            message: message.into(),
        });
    }

    /// A placeholder after an error, so checking continues and reports more.
    fn bad() -> (Node, Ty, u64) {
        (Node::Const(Const::Null), Ty::Dyn, 1)
    }

    /// The bound on how many elements a list-valued node has.
    fn bound_of(node: &Node) -> u64 {
        match node {
            Node::Const(Const::List(l)) => l.len() as u64,
            Node::Const(Const::Map(m)) => m.len() as u64,
            Node::List(items) => items.len() as u64,
            Node::Map(items) => items.len() as u64,
            Node::Field(f) if f.is_stmt() => FACT_LIST_BOUND,
            Node::Field(_) => CTX_LIST_BOUND,
            Node::Call(Func::StmtValues | Func::StmtFilterValues, _) => FACT_LIST_BOUND,
            Node::Comp { range, .. } => Self::bound_of(range),
            Node::Bin(BinOp::Add, a, b) => Self::bound_of(a) + Self::bound_of(b),
            _ => FACT_LIST_BOUND,
        }
    }

    fn check(&mut self, e: &Expr) -> (Node, Ty, u64) {
        match &e.kind {
            ExprKind::Lit(l) => {
                let c = match l {
                    Lit::Null => Const::Null,
                    Lit::Bool(b) => Const::Bool(*b),
                    Lit::Int(i) => Const::Int(*i),
                    Lit::Uint(u) => Const::Uint(*u),
                    Lit::Double(d) => Const::Double(*d),
                    Lit::Str(s) => Const::Str(s.clone()),
                };
                let ty = of_const(&c);
                (Node::Const(c), ty, 1)
            }
            ExprKind::Ident(name) => self.ident(name, e.pos),
            ExprKind::Select(operand, field) => self.select(operand, field, e.pos),
            ExprKind::Has(operand, field) => self.has(operand, field, e.pos),
            ExprKind::Index(a, b) => {
                let (na, ta, ca) = self.check(a);
                let (nb, tb, cb) = self.check(b);
                let ty = match (&ta, &tb) {
                    (Ty::List(t), Ty::Int | Ty::Uint | Ty::Dyn) => (**t).clone(),
                    (Ty::Map(k, v), key) if k.comparable_eq(key) => (**v).clone(),
                    (Ty::Dyn, _) => Ty::Dyn,
                    (Ty::Obj(r), _) => {
                        self.error(
                            e.pos,
                            format!("`{}` cannot be indexed; select a field", r.name()),
                        );
                        Ty::Dyn
                    }
                    _ => {
                        self.error(
                            e.pos,
                            format!("cannot index a {} with a {}", ta.name(), tb.name()),
                        );
                        Ty::Dyn
                    }
                };
                (Node::Index(Box::new(na), Box::new(nb)), ty, ca + cb + 1)
            }
            ExprKind::Unary(op, operand) => {
                let (n, t, c) = self.check(operand);
                self.not_obj(&t, operand.pos);
                match op {
                    UnOp::Not => {
                        if !matches!(t, Ty::Bool | Ty::Dyn) {
                            self.error(e.pos, format!("`!` needs a bool, got {}", t.name()));
                        }
                        (Node::Not(Box::new(n)), Ty::Bool, c + 1)
                    }
                    UnOp::Neg => {
                        if !matches!(t, Ty::Int | Ty::Double | Ty::Duration | Ty::Dyn) {
                            self.error(
                                e.pos,
                                format!("unary `-` needs a number, got {}", t.name()),
                            );
                        }
                        (Node::Neg(Box::new(n)), t, c + 1)
                    }
                }
            }
            ExprKind::Binary(op, a, b) => self.binary(*op, a, b, e.pos),
            ExprKind::Cond(c, a, b) => {
                let (nc, tc, cc) = self.check(c);
                if !matches!(tc, Ty::Bool | Ty::Dyn) {
                    self.error(
                        c.pos,
                        format!("the condition of `?:` must be a bool, got {}", tc.name()),
                    );
                }
                let (na, ta, ca) = self.check(a);
                let (nb, tb, cb) = self.check(b);
                self.not_obj(&ta, a.pos);
                self.not_obj(&tb, b.pos);
                (
                    Node::Cond(Box::new(nc), Box::new(na), Box::new(nb)),
                    Ty::join(ta, tb),
                    cc + ca.max(cb) + 1,
                )
            }
            ExprKind::List(items) => {
                let mut nodes = Vec::new();
                let mut ty: Option<Ty> = None;
                let mut cost = 1;
                for it in items {
                    let (n, t, c) = self.check(it);
                    self.not_obj(&t, it.pos);
                    ty = Some(match ty {
                        None => t,
                        Some(prev) => Ty::join(prev, t),
                    });
                    nodes.push(n);
                    cost += c;
                }
                (
                    Node::List(nodes),
                    Ty::List(Box::new(ty.unwrap_or(Ty::Dyn))),
                    cost,
                )
            }
            ExprKind::Map(entries) => {
                let mut nodes = Vec::new();
                let mut cost = 1;
                let (mut kt, mut vt): (Option<Ty>, Option<Ty>) = (None, None);
                for (k, v) in entries {
                    let (nk, tk, ck) = self.check(k);
                    let (nv, tv, cv) = self.check(v);
                    if !matches!(tk, Ty::String | Ty::Int | Ty::Uint | Ty::Bool | Ty::Dyn) {
                        self.error(
                            k.pos,
                            format!(
                                "map keys must be string, int, uint or bool, got {}",
                                tk.name()
                            ),
                        );
                    }
                    self.not_obj(&tv, v.pos);
                    kt = Some(kt.map_or(tk.clone(), |p| Ty::join(p, tk)));
                    vt = Some(vt.map_or(tv.clone(), |p| Ty::join(p, tv)));
                    nodes.push((nk, nv));
                    cost += ck + cv;
                }
                (
                    Node::Map(nodes),
                    Ty::Map(
                        Box::new(kt.unwrap_or(Ty::Dyn)),
                        Box::new(vt.unwrap_or(Ty::Dyn)),
                    ),
                    cost,
                )
            }
            ExprKind::Call { target, func, args } => {
                self.call(target.as_deref(), func, args, e.pos)
            }
            ExprKind::Comprehension {
                mac,
                range,
                var,
                pred,
                body,
            } => self.comprehension(*mac, range, var, pred.as_deref(), body.as_deref(), e.pos),
        }
    }

    fn not_obj(&mut self, t: &Ty, pos: usize) {
        if let Ty::Obj(r) = t {
            self.error(
                pos,
                format!("`{}` is not a value; select one of its fields", r.name()),
            );
        }
    }

    fn ident(&mut self, name: &str, pos: usize) -> (Node, Ty, u64) {
        if let Some((_, slot, ty)) = self.scopes.iter().rev().find(|(n, _, _)| n == name) {
            return (Node::Var(*slot), ty.clone(), 1);
        }
        let root = match name {
            "principal" => Root::Principal,
            "stmt" => Root::Stmt,
            "db" => Root::Db,
            "time" => Root::Time,
            "session" => Root::Session,
            "ticket" => Root::Ticket,
            "vars" => Root::Vars,
            "WEAK" => return (Node::Const(Const::Int(1)), Ty::Int, 1),
            "MEDIUM" => return (Node::Const(Const::Int(2)), Ty::Int, 1),
            "STRONG" => return (Node::Const(Const::Int(3)), Ty::Int, 1),
            "now" => {
                self.error(
                    pos,
                    "there is no clock in a policy: use `time.now`, which the host supplies",
                );
                return Self::bad();
            }
            other => {
                if let Some((_, why)) = LATER.iter().find(|(n, _)| *n == other) {
                    self.error(pos, format!("`{other}` is not available: {why}"));
                    return Self::bad();
                }
                let roots = [
                    "principal",
                    "stmt",
                    "db",
                    "time",
                    "session",
                    "ticket",
                    "vars",
                ];
                let hint = similar(other, roots.iter().copied())
                    .map(|s| format!("; did you mean `{s}`?"))
                    .unwrap_or_default();
                self.error(pos, format!("unknown identifier `{other}`{hint}"));
                return Self::bad();
            }
        };
        (Node::Const(Const::Null), Ty::Obj(root), 0)
    }

    fn select(&mut self, operand: &Expr, field: &str, pos: usize) -> (Node, Ty, u64) {
        let (n, t, c) = self.check(operand);
        match t {
            Ty::Obj(Root::Vars) => match self.vars.get(field) {
                Some(v) => (Node::Const(v.clone()), of_const(v), 1),
                None => {
                    let hint = similar(field, self.vars.keys().map(String::as_str))
                        .map(|s| format!("; did you mean `vars.{s}`?"))
                        .unwrap_or_default();
                    self.error(
                        pos,
                        format!("`vars.{field}` is not declared under `vars:`{hint}"),
                    );
                    Self::bad()
                }
            },
            Ty::Obj(root) => match FIELDS.iter().find(|d| d.root == root && d.name == field) {
                Some(d) => {
                    self.info.fields.insert(d.field);
                    (Node::Field(d.field), (d.ty)(), 1)
                }
                None => {
                    let path = format!("{}.{field}", root.name());
                    if let Some((_, why)) = LATER.iter().find(|(n, _)| *n == path) {
                        self.error(pos, format!("`{path}` is not available: {why}"));
                    } else {
                        let names = FIELDS.iter().filter(|d| d.root == root).map(|d| d.name);
                        let hint = similar(field, names)
                            .map(|s| format!("; did you mean `{}.{s}`?", root.name()))
                            .unwrap_or_default();
                        self.error(pos, format!("`{path}` is not a field{hint}"));
                    }
                    Self::bad()
                }
            },
            Ty::Map(_, v) => (Node::Select(Box::new(n), field.to_string()), *v, c + 1),
            Ty::Dyn => (Node::Select(Box::new(n), field.to_string()), Ty::Dyn, c + 1),
            other => {
                self.error(
                    pos,
                    format!("cannot select `.{field}` on a {}", other.name()),
                );
                Self::bad()
            }
        }
    }

    fn has(&mut self, operand: &Expr, field: &str, pos: usize) -> (Node, Ty, u64) {
        let (n, t, c) = self.check(operand);
        match t {
            Ty::Obj(Root::Vars) => (
                Node::Const(Const::Bool(self.vars.contains_key(field))),
                Ty::Bool,
                1,
            ),
            Ty::Obj(root) => match FIELDS.iter().find(|d| d.root == root && d.name == field) {
                Some(d) => {
                    self.info.fields.insert(d.field);
                    (Node::HasField(d.field), Ty::Bool, 1)
                }
                None => {
                    self.error(pos, format!("`{}.{field}` is not a field", root.name()));
                    Self::bad()
                }
            },
            Ty::Map(..) | Ty::Dyn => (
                Node::HasKey(Box::new(n), field.to_string()),
                Ty::Bool,
                c + 1,
            ),
            other => {
                self.error(
                    pos,
                    format!(
                        "`has()` needs a field of an object or a map, got {}",
                        other.name()
                    ),
                );
                Self::bad()
            }
        }
    }

    fn binary(&mut self, op: BinOp, a: &Expr, b: &Expr, pos: usize) -> (Node, Ty, u64) {
        let (na, ta, ca) = self.check(a);
        let (nb, tb, cb) = self.check(b);
        self.not_obj(&ta, a.pos);
        self.not_obj(&tb, b.pos);
        let cost = ca + cb + 1;
        let (na, nb) = (Box::new(na), Box::new(nb));
        match op {
            BinOp::And | BinOp::Or => {
                for (t, p) in [(&ta, a.pos), (&tb, b.pos)] {
                    if !matches!(t, Ty::Bool | Ty::Dyn) {
                        self.error(
                            p,
                            format!("`{}` needs bools, got {}", op.symbol(), t.name()),
                        );
                    }
                }
                let node = if op == BinOp::And {
                    Node::And(na, nb)
                } else {
                    Node::Or(na, nb)
                };
                (node, Ty::Bool, cost)
            }
            BinOp::Eq | BinOp::Ne => {
                if !ta.comparable_eq(&tb) {
                    self.error(
                        pos,
                        format!(
                            "`{}` between {} and {} is always {}",
                            op.symbol(),
                            ta.name(),
                            tb.name(),
                            op == BinOp::Ne
                        ),
                    );
                }
                (Node::Bin(op, na, nb), Ty::Bool, cost)
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                if !ta.orderable_with(&tb) {
                    self.error(
                        pos,
                        format!("no ordering between {} and {}", ta.name(), tb.name()),
                    );
                }
                (Node::Bin(op, na, nb), Ty::Bool, cost)
            }
            BinOp::In => {
                match tb.elem() {
                    Some(el) if el.comparable_eq(&ta) => {}
                    Some(el) => self.error(
                        pos,
                        format!(
                            "`in` a container of {} with a {} is always false",
                            el.name(),
                            ta.name()
                        ),
                    ),
                    None => self.error(
                        pos,
                        format!("`in` needs a list or a map, got {}", tb.name()),
                    ),
                }
                let bound = Self::bound_of(&nb);
                (Node::Bin(op, na, nb), Ty::Bool, cost + bound)
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => {
                let ty = arith(op, &ta, &tb);
                match ty {
                    Some(t) => (Node::Bin(op, na, nb), t, cost),
                    None => {
                        self.error(
                            pos,
                            format!(
                                "no overload for `{}` on {} and {}",
                                op.symbol(),
                                ta.name(),
                                tb.name()
                            ),
                        );
                        Self::bad()
                    }
                }
            }
        }
    }

    fn arg_const_str(&mut self, e: &Expr, what: &str) -> Option<String> {
        match &e.kind {
            ExprKind::Lit(Lit::Str(s)) => Some(s.clone()),
            // `vars.x` holding a string: a constant too.
            ExprKind::Select(op, f) if matches!(op.kind, ExprKind::Ident(ref r) if r == "vars") => {
                match self.vars.get(f) {
                    Some(Const::Str(s)) => Some(s.clone()),
                    _ => {
                        self.error(
                            e.pos,
                            format!("{what} must be a string literal or a string under `vars:`"),
                        );
                        None
                    }
                }
            }
            _ => {
                self.error(
                    e.pos,
                    format!("{what} must be a string literal or a string under `vars:`"),
                );
                None
            }
        }
    }

    fn call(
        &mut self,
        target: Option<&Expr>,
        func: &str,
        args: &[Expr],
        pos: usize,
    ) -> (Node, Ty, u64) {
        if target.is_none() && func == "now" {
            self.error(
                pos,
                "there is no clock in a policy: use `time.now`, which the host supplies",
            );
            return Self::bad();
        }
        // Constant constructors, folded here.
        if target.is_none() && (func == "timestamp" || func == "duration") {
            if args.len() != 1 {
                self.error(pos, format!("`{func}` takes one string literal"));
                return Self::bad();
            }
            let Some(s) = self.arg_const_str(&args[0], &format!("the argument of `{func}`")) else {
                return Self::bad();
            };
            return if func == "timestamp" {
                match time::parse_timestamp(&s, false) {
                    Some(t) => (Node::Const(Const::Timestamp(t)), Ty::Timestamp, 1),
                    None => {
                        self.error(
                            args[0].pos,
                            format!("`{s}` is not an RFC 3339 timestamp (2026-10-21T14:00:00Z)"),
                        );
                        Self::bad()
                    }
                }
            } else {
                match time::parse_duration(&s) {
                    Some(d) => (Node::Const(Const::Duration(d)), Ty::Duration, 1),
                    None => {
                        self.error(
                            args[0].pos,
                            format!("`{s}` is not a duration (2160h, 90m, 30s)"),
                        );
                        Self::bad()
                    }
                }
            };
        }
        if target.is_none() && func == "in_window" {
            if args.len() != 3 {
                self.error(
                    pos,
                    "`in_window` takes a timestamp, a window spec and a time zone",
                );
                return Self::bad();
            }
            let (nt, tt, ct) = self.check(&args[0]);
            if !matches!(tt, Ty::Timestamp | Ty::Dyn) {
                self.error(
                    args[0].pos,
                    format!("`in_window` needs a timestamp, got {}", tt.name()),
                );
            }
            let spec = self.arg_const_str(&args[1], "the window spec of `in_window`");
            let tz = self.arg_const_str(&args[2], "the time zone of `in_window`");
            let (Some(spec), Some(tz)) = (spec, tz) else {
                return Self::bad();
            };
            let spec = match WindowSpec::parse(&spec) {
                Ok(w) => w,
                Err(why) => {
                    self.error(args[1].pos, why);
                    return Self::bad();
                }
            };
            let tz = TzSpec::parse(&tz);
            if let TzSpec::Named(name) = &tz {
                self.warn(
                    args[2].pos,
                    format!(
                        "`{name}` is decided only when it is the workspace time zone the host passes \
                         (time.tz); any other zone is UNKNOWN. UTC and fixed offsets (+01:00) always work"
                    ),
                );
                self.info.named_zones.push(name.clone());
            }
            self.info.fields.insert(Field::TimeTz);
            return (
                Node::InWindow(Box::new(nt), Arc::new(spec), tz),
                Ty::Bool,
                ct + 8,
            );
        }
        if func == "matches" {
            let (Some(t), [pat]) = (target, args) else {
                self.error(pos, "`matches` is a method: s.matches('pattern')");
                return Self::bad();
            };
            let (nt, tt, ct) = self.check(t);
            if !matches!(tt, Ty::String | Ty::Dyn) {
                self.error(
                    t.pos,
                    format!("`matches` needs a string, got {}", tt.name()),
                );
            }
            let Some(p) = self.arg_const_str(pat, "the pattern of `matches`") else {
                return Self::bad();
            };
            if p.len() > MAX_REGEX_BYTES {
                self.error(
                    pat.pos,
                    format!(
                        "the pattern is {} bytes; the limit is {MAX_REGEX_BYTES}",
                        p.len()
                    ),
                );
                return Self::bad();
            }
            return match regex::RegexBuilder::new(&p)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
            {
                Ok(re) => (Node::Matches(Box::new(nt), Arc::new(re)), Ty::Bool, ct + 16),
                Err(e) => {
                    self.error(pat.pos, format!("invalid pattern: {e}"));
                    Self::bad()
                }
            };
        }

        // Methods on `stmt`.
        if let Some(t) = target {
            if matches!(&t.kind, ExprKind::Ident(n) if n == "stmt" && !self.scopes.iter().any(|(v, _, _)| v == "stmt"))
            {
                let f = match func {
                    "values" => Func::StmtValues,
                    "filter_values" => Func::StmtFilterValues,
                    "has_filter" => Func::StmtHasFilter,
                    "lower_bound" => Func::StmtLowerBound,
                    "upper_bound" => Func::StmtUpperBound,
                    "reads" => Func::StmtReads,
                    "writes" => Func::StmtWrites,
                    "touches" => Func::StmtTouches,
                    other => {
                        let names = [
                            "values",
                            "filter_values",
                            "has_filter",
                            "lower_bound",
                            "upper_bound",
                            "reads",
                            "writes",
                            "touches",
                        ];
                        let hint = similar(other, names.iter().copied())
                            .map(|s| format!("; did you mean `stmt.{s}`?"))
                            .unwrap_or_default();
                        self.error(pos, format!("`stmt.{other}()` is not a function{hint}"));
                        return Self::bad();
                    }
                };
                if args.len() != 1 {
                    self.error(pos, format!("`stmt.{func}` takes one string"));
                    return Self::bad();
                }
                let (na, ta, ca) = self.check(&args[0]);
                if !matches!(ta, Ty::String | Ty::Dyn) {
                    self.error(
                        args[0].pos,
                        format!("`stmt.{func}` needs a string, got {}", ta.name()),
                    );
                }
                self.info.reads_stmt = true;
                let ty = match f {
                    Func::StmtValues | Func::StmtFilterValues => Ty::List(Box::new(Ty::Dyn)),
                    Func::StmtLowerBound | Func::StmtUpperBound => Ty::Dyn,
                    _ => Ty::Bool,
                };
                return (Node::Call(f, vec![na]), ty, ca + 8);
            }
        }

        // Everything else: the stdlib subset and the pure helpers.
        let mut nodes = Vec::new();
        let mut tys = Vec::new();
        let mut cost = 1;
        if let Some(t) = target {
            let (n, ty, c) = self.check(t);
            self.not_obj(&ty, t.pos);
            nodes.push(n);
            tys.push(ty);
            cost += c;
        }
        for a in args {
            let (n, ty, c) = self.check(a);
            self.not_obj(&ty, a.pos);
            nodes.push(n);
            tys.push(ty);
            cost += c;
        }
        let method = target.is_some();
        let sig = |want_method: bool, n: usize| method == want_method && tys.len() == n;
        let s = |t: &Ty| matches!(t, Ty::String | Ty::Dyn);
        let (f, ty) = match func {
            "size" if sig(true, 1) || sig(false, 1) => {
                if !matches!(tys[0], Ty::String | Ty::List(_) | Ty::Map(..) | Ty::Dyn) {
                    self.error(pos, format!("no overload for size() on {}", tys[0].name()));
                }
                (Func::Size, Ty::Int)
            }
            "int" if sig(false, 1) => (Func::Int, Ty::Int),
            "uint" if sig(false, 1) => (Func::Uint, Ty::Uint),
            "double" if sig(false, 1) => (Func::Double, Ty::Double),
            "string" if sig(false, 1) => (Func::String, Ty::String),
            "bool" if sig(false, 1) => (Func::Bool, Ty::Bool),
            "dyn" if sig(false, 1) => (Func::Dyn, Ty::Dyn),
            "contains" | "startsWith" | "endsWith" if sig(true, 2) => {
                if !s(&tys[0]) || !s(&tys[1]) {
                    self.error(pos, format!("`{func}` is a string method taking a string"));
                }
                let f = match func {
                    "contains" => Func::Contains,
                    "startsWith" => Func::StartsWith,
                    _ => Func::EndsWith,
                };
                (f, Ty::Bool)
            }
            "glob" if sig(false, 2) => {
                if !s(&tys[0]) || !s(&tys[1]) {
                    self.error(pos, "`glob` takes two strings");
                }
                (Func::Glob, Ty::Bool)
            }
            "cidr_contains" if sig(false, 2) => {
                if !s(&tys[0]) || !s(&tys[1]) {
                    self.error(pos, "`cidr_contains` takes two strings (cidr, ip)");
                }
                (Func::CidrContains, Ty::Bool)
            }
            "size" | "int" | "uint" | "double" | "string" | "bool" | "dyn" | "contains"
            | "startsWith" | "endsWith" | "glob" | "cidr_contains" => {
                self.error(
                    pos,
                    format!("wrong number of arguments or call style for `{func}`"),
                );
                return Self::bad();
            }
            other => {
                let known = [
                    "size",
                    "int",
                    "uint",
                    "double",
                    "string",
                    "bool",
                    "contains",
                    "startsWith",
                    "endsWith",
                    "matches",
                    "glob",
                    "cidr_contains",
                    "in_window",
                    "timestamp",
                    "duration",
                ];
                let hint = similar(other, known.iter().copied())
                    .map(|s| format!("; did you mean `{s}`?"))
                    .unwrap_or_default();
                self.error(
                    pos,
                    format!("`{other}` is not an allowed function (CEL standard subset and Vericto helpers only){hint}"),
                );
                return Self::bad();
            }
        };
        // String operations cost with the string; strings are bounded by
        // the statement and the context, so a flat factor keeps the bound.
        (Node::Call(f, nodes), ty, cost + 4)
    }

    fn comprehension(
        &mut self,
        mac: Macro,
        range: &Expr,
        var: &str,
        pred: Option<&Expr>,
        body: Option<&Expr>,
        pos: usize,
    ) -> (Node, Ty, u64) {
        let (nr, tr, cr) = self.check(range);
        let elem = match tr.elem() {
            Some(t) => t,
            None => {
                self.error(
                    range.pos,
                    format!(
                        "`{}` ranges over a list or a map, got {}",
                        mac.name(),
                        tr.name()
                    ),
                );
                Ty::Dyn
            }
        };
        self.nesting += 1;
        if self.nesting > MAX_COMPREHENSION_NESTING {
            self.error(
                pos,
                format!("comprehensions nest deeper than {MAX_COMPREHENSION_NESTING}"),
            );
        }
        let slot = self.slots;
        self.slots += 1;
        self.scopes.push((var.to_string(), slot, elem));
        let mut inner = 0;
        let np = pred.map(|p| {
            let (n, t, c) = self.check(p);
            if !matches!(t, Ty::Bool | Ty::Dyn) {
                self.error(
                    p.pos,
                    format!(
                        "the predicate of `{}` must be a bool, got {}",
                        mac.name(),
                        t.name()
                    ),
                );
            }
            inner += c;
            Box::new(n)
        });
        let mut body_ty = Ty::Dyn;
        let nb = body.map(|b| {
            let (n, t, c) = self.check(b);
            self.not_obj(&t, b.pos);
            body_ty = t;
            inner += c;
            Box::new(n)
        });
        self.scopes.pop();
        self.nesting -= 1;
        let bound = Self::bound_of(&nr);
        let ty = match mac {
            Macro::All | Macro::Exists | Macro::ExistsOne => Ty::Bool,
            Macro::Map | Macro::MapFilter => Ty::List(Box::new(body_ty)),
            Macro::Filter => match &tr {
                Ty::Map(k, _) => Ty::List(k.clone()),
                Ty::List(t) => Ty::List(t.clone()),
                _ => Ty::List(Box::new(Ty::Dyn)),
            },
        };
        let cost = cr + bound.saturating_mul(inner + 1) + 1;
        (
            Node::Comp {
                mac,
                range: Box::new(nr),
                slot,
                pred: np,
                body: nb,
            },
            ty,
            cost,
        )
    }
}

fn arith(op: BinOp, a: &Ty, b: &Ty) -> Option<Ty> {
    use Ty::*;
    Some(match (op, a, b) {
        (_, Dyn, _) | (_, _, Dyn) => Dyn,
        (_, Int, Int) => Int,
        (_, Uint, Uint) => Uint,
        (BinOp::Rem, Double, Double) => return None,
        (_, Double, Double) => Double,
        (BinOp::Add, String, String) => String,
        (BinOp::Add, List(x), List(y)) => List(Box::new(Ty::join((**x).clone(), (**y).clone()))),
        (BinOp::Add, Timestamp, Duration) | (BinOp::Add, Duration, Timestamp) => Timestamp,
        (BinOp::Sub, Timestamp, Duration) => Timestamp,
        (BinOp::Sub, Timestamp, Timestamp) => Duration,
        (BinOp::Add | BinOp::Sub, Duration, Duration) => Duration,
        _ => return None,
    })
}

/// Whether a field is decidable in a mode: `Ok` when it is always present
/// there, `Err(true)` when the caller must declare it, `Err(false)` when it
/// is absent (UNKNOWN).
pub(crate) fn availability(f: Field, mode: HostMode) -> Result<(), bool> {
    match f.def().avail {
        Avail::Static => Ok(()),
        Avail::Declared(m) => Err(m.contains(&mode)),
        Avail::Only(m) => {
            if m.contains(&mode) {
                Ok(())
            } else {
                Err(false)
            }
        }
        Avail::DeclaredInCi => {
            if mode == HostMode::Ci {
                Err(true)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(src: &str) -> Compiled {
        compile(src, &BTreeMap::new()).unwrap_or_else(|e| panic!("{src}: {e:?}"))
    }

    fn fails(src: &str) -> String {
        match compile(src, &BTreeMap::new()) {
            Ok(_) => panic!("{src} should not compile"),
            Err(e) => e
                .iter()
                .map(|d| d.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        }
    }

    #[test]
    fn accepts_the_design_examples() {
        ok(r#"principal.type in ["agent", "human"]"#);
        ok(r#"stmt.values("public.refunds.amount").exists(v, v > 200)"#);
        ok(
            r#"stmt.tables.all(t, !(t in ["public.invoices"]) || stmt.has_filter(t + ".tenant_id"))"#,
        );
        ok(
            r#"has(session.tenant) && stmt.filter_values("public.invoices.tenant_id").all(v, string(v) == session.tenant)"#,
        );
        ok(r#"stmt.lower_bound("public.events.created_at") >= time.now - duration("2160h")"#);
        ok(r#"!has(stmt.limit) || stmt.limit > 1000"#);
        ok(r#"stmt.op != "select" && !(has(ticket.id) && ticket.id.matches("^OPS-[0-9]+$"))"#);
        ok(r#"principal.type == "pipeline" && in_window(time.now, "Tue,Thu 14:00-16:00", "UTC")"#);
        ok(r#"stmt.op != "select" || stmt.tables.exists(t, !t.startsWith("reporting."))"#);
        ok(r#"principal.trust >= STRONG && db.env == "prod""#);
        ok(r#"double(principal.attrs.max_refund) > 1.5"#);
        ok(r#"cidr_contains("10.0.0.0/8", session.client_ip)"#);
    }

    #[test]
    fn refuses_with_reasons() {
        assert!(fails("principl.type == 'agent'").contains("did you mean `principal`"));
        assert!(fails("principal.typ == 'agent'").contains("did you mean `principal.type`"));
        assert!(fails("now() > 1").contains("no clock"));
        assert!(fails("nope(1) > 1").contains("not an allowed function"));
        assert!(fails("now > 1").contains("no clock"));
        assert!(fails("params[0] > 1").contains("Phase 2"));
        assert!(fails("approval.granted").contains("Phase 3"));
        assert!(fails("stmt.columns_projected.size() > 0").contains("not available"));
        assert!(fails("principal.type == 1").contains("always false"));
        assert!(fails("principal.trust < 'x'").contains("no ordering"));
        assert!(fails("stmt.tables > 1").contains("no ordering"));
        assert!(fails("principal").contains("not a value"));
        assert!(fails("ticket.id.matches(ticket.id)").contains("string literal"));
        assert!(fails("ticket.id.matches('(')").contains("invalid pattern"));
        assert!(fails("duration('5d') > duration('1h')").contains("not a duration"));
        assert!(fails("in_window(time.now, 'Funday 10:00-11:00', 'UTC')").contains("unknown day"));
        assert!(fails("stmt.valuez('a.b.c').size() > 0").contains("did you mean `stmt.values`"));
        assert!(fails("vars.limit > 1").contains("not declared"));
        assert!(fails("1 + 1.0 > 0").contains("no overload"));
        assert!(fails("'a' in 'abc'").contains("list or a map"));
    }

    #[test]
    fn static_bounds() {
        let long = format!("'{}' == 'a'", "x".repeat(MAX_EXPR_BYTES));
        assert!(fails(&long).contains("bytes"));
        let many = vec!["true"; 200].join(" && ");
        assert!(fails(&many).contains("nodes"));
        assert!(
            fails("stmt.tables.all(a, stmt.tables.all(b, stmt.tables.all(c, a == b)))")
                .contains("nest")
        );
        // Two nested comprehensions over facts: 1024 × 1024 is over the cost.
        assert!(
            fails("stmt.tables.all(a, stmt.columns_read.exists(b, b.startsWith(a)))")
                .contains("cost")
        );
        // Over a small constant list it is fine.
        let mut vars = BTreeMap::new();
        vars.insert(
            "t".to_string(),
            Const::List(vec![Const::Str("a".into()), Const::Str("b".into())]),
        );
        compile(
            "stmt.tables.all(a, vars.t.exists(b, a.startsWith(b)))",
            &vars,
        )
        .unwrap();
        let pat = format!("ticket.id.matches('{}')", "a".repeat(MAX_REGEX_BYTES + 1));
        assert!(fails(&pat).contains("limit"));
    }

    #[test]
    fn records_fields_and_warnings() {
        let c = ok("session.tenant == 'a' && stmt.op == 'select'");
        assert!(c.info.fields.contains(&Field::SessionTenant));
        assert!(c.info.reads_stmt);
        let c = ok("in_window(time.now, 'Mon-Fri 09:00-18:00', 'Europe/Madrid')");
        assert_eq!(c.info.warnings.len(), 1);
        assert!(!c.info.reads_stmt);
        assert_eq!(
            availability(Field::SessionTenant, HostMode::Mcp),
            Err(false)
        );
        assert_eq!(
            availability(Field::SessionTenant, HostMode::RuntimeApi),
            Err(true)
        );
        assert_eq!(
            availability(Field::SessionClientIp, HostMode::Proxy),
            Ok(())
        );
        assert_eq!(availability(Field::DbEnv, HostMode::Ci), Err(true));
        assert_eq!(availability(Field::StmtTables, HostMode::Ci), Ok(()));
    }
}
