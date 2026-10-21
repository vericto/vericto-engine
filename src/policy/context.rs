// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! What the host declares about a statement besides its text: who runs it
//! (the principal), where (the database), when (the time, in the workspace
//! time zone), and the session context (ticket, tenant, weak signals).
//!
//! The engine never computes any of it. A field the host leaves out is
//! *absent*: `has()` on it is false, and reading it is UNKNOWN, which the
//! policy's `on_unknown` decides (design §4.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The kind of principal (design §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrincipalType {
    Agent,
    Service,
    Human,
    Pipeline,
    Tool,
    /// Matched no mapping, or matched more than one at the same trust.
    Unknown,
}

impl PrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalType::Agent => "agent",
            PrincipalType::Service => "service",
            PrincipalType::Human => "human",
            PrincipalType::Pipeline => "pipeline",
            PrincipalType::Tool => "tool",
            PrincipalType::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<PrincipalType> {
        Some(match s {
            "agent" => PrincipalType::Agent,
            "service" => PrincipalType::Service,
            "human" => PrincipalType::Human,
            "pipeline" => PrincipalType::Pipeline,
            "tool" => PrincipalType::Tool,
            "unknown" => PrincipalType::Unknown,
            _ => return None,
        })
    }

    pub(crate) fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// How strongly the principal was identified: the trust of the signal that
/// identified it (design §3.2). `Ord`: `Weak < Medium < Strong`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trust {
    /// application_name, client IP / CIDR, listener.
    Weak = 1,
    /// A dedicated database user, a static API key.
    Medium = 2,
    /// OIDC-minted identity, mTLS client certificate.
    Strong = 3,
}

impl Trust {
    pub fn level(self) -> i64 {
        self as i64
    }

    /// `weak`/`medium`/`strong`, or `1`/`2`/`3`.
    pub fn parse(s: &str) -> Option<Trust> {
        Some(match s {
            "weak" | "1" => Trust::Weak,
            "medium" | "2" => Trust::Medium,
            "strong" | "3" => Trust::Strong,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Weak => "weak",
            Trust::Medium => "medium",
            Trust::Strong => "strong",
        }
    }
}

impl Serialize for Trust {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Trust {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(i64),
            S(String),
        }
        let s = match Raw::deserialize(d)? {
            Raw::N(n) => n.to_string(),
            Raw::S(s) => s,
        };
        Trust::parse(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown trust `{s}` (weak, medium, strong or 1, 2, 3)"
            ))
        })
    }
}

/// The principal running the statement, as the host resolved it (once per
/// session in the proxy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Principal {
    /// The mapped id (`svc-billing`), or the db_user / key id when unmatched.
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub trust: Trust,
    /// The signal that identified it: `mtls`, `oidc`, `api_key`, `db_user`,
    /// `application_name`, `cidr`, `listener`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Responsible human(s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    /// IdP groups (OIDC/SSO only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// An end user asserted by a calling service (Runtime API), with the
    /// key's trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_user: Option<BTreeMap<String, String>>,
}

impl Principal {
    pub fn new(id: impl Into<String>, principal_type: PrincipalType, trust: Trust) -> Self {
        Principal {
            id: id.into(),
            principal_type,
            trust,
            via: None,
            owner: None,
            attrs: BTreeMap::new(),
            groups: Vec::new(),
            end_user: None,
        }
    }

    /// What an unidentified statement runs as: `unknown`, weak.
    pub fn unknown() -> Self {
        Principal::new("", PrincipalType::Unknown, Trust::Weak)
    }
}

/// The evaluating host (a policy's `modes:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HostMode {
    Proxy,
    RuntimeApi,
    Mcp,
    Ci,
}

impl HostMode {
    pub fn as_str(self) -> &'static str {
        match self {
            HostMode::Proxy => "proxy",
            HostMode::RuntimeApi => "runtime_api",
            HostMode::Mcp => "mcp",
            HostMode::Ci => "ci",
        }
    }

    pub fn parse(s: &str) -> Option<HostMode> {
        Some(match s {
            "proxy" => HostMode::Proxy,
            "runtime_api" => HostMode::RuntimeApi,
            "mcp" => HostMode::Mcp,
            "ci" => HostMode::Ci,
            _ => return None,
        })
    }

    pub const ALL: [HostMode; 4] = [
        HostMode::Proxy,
        HostMode::RuntimeApi,
        HostMode::Mcp,
        HostMode::Ci,
    ];
}

/// The database record (`db.*`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DbContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `prod`, `staging`, `dev`: set in the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// The time of the statement, from the host (`time.*`). The engine reads
/// no clock: the proxy passes its clock, the simulator the event's
/// `occurred_at`, CI the run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TimeContext {
    /// Seconds since the Unix epoch.
    pub now_unix: i64,
    /// The workspace time zone (IANA name, or `UTC`).
    #[serde(default = "utc")]
    pub tz: String,
    /// The zone's offset from UTC at `now_unix`, in seconds (the host has
    /// the time-zone database; the engine has none).
    #[serde(default)]
    pub utc_offset_secs: i32,
}

fn utc() -> String {
    "UTC".to_string()
}

impl TimeContext {
    pub fn utc(now_unix: i64) -> Self {
        TimeContext {
            now_unix,
            tz: utc(),
            utc_offset_secs: 0,
        }
    }

    pub fn in_zone(now_unix: i64, tz: impl Into<String>, utc_offset_secs: i32) -> Self {
        TimeContext {
            now_unix,
            tz: tz.into(),
            utc_offset_secs,
        }
    }
}

/// A change ticket (`ticket.*`), declared by the session (`SET
/// vericto.ticket`), an API or MCP field, or a CLI flag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Ticket {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// True only after a ticketing lookup (Phase 3).
    #[serde(default)]
    pub verified: bool,
}

impl Ticket {
    pub fn declared(id: impl Into<String>) -> Self {
        Ticket {
            id: id.into(),
            source: None,
            verified: false,
        }
    }
}

/// Session context (`session.*`): the set-once tenant and the weak signals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener: Option<String>,
}

/// Everything a host declares about one statement, besides its SQL.
///
/// JSON (the eval sidecar, the simulator):
/// `{"mode":"proxy","principal":{"id":"agent-support-bot","type":"agent","trust":"medium"},
///   "db":{"id":"db_1","env":"prod"},"time":{"now_unix":1792600000,"tz":"Europe/Madrid","utc_offset_secs":7200}}`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EvalContext {
    /// The evaluating host. `None`: every policy applies, whatever its
    /// `modes:` (the conservative reading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<HostMode>,
    /// `None`: the statement runs as `unknown`, weak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<DbContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<TimeContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<Ticket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContext>,
    /// The schema unqualified names resolve to, set by the host as for
    /// [`crate::AccessPolicy::default_schema`]: on MySQL the connection's
    /// database, on Postgres the first schema of a known `search_path`.
    /// `None`: `public` on Postgres, `dbo` on SQL Server, `main` on SQLite,
    /// unknown on MySQL, Oracle and Snowflake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_schema: Option<String>,
}

impl EvalContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mode(mut self, mode: HostMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn with_principal(mut self, p: Principal) -> Self {
        self.principal = Some(p);
        self
    }

    pub fn with_db(mut self, db: DbContext) -> Self {
        self.db = Some(db);
        self
    }

    pub fn with_time(mut self, t: TimeContext) -> Self {
        self.time = Some(t);
        self
    }

    pub fn with_ticket(mut self, t: Ticket) -> Self {
        self.ticket = Some(t);
        self
    }

    pub fn with_session(mut self, s: SessionContext) -> Self {
        self.session = Some(s);
        self
    }

    pub fn with_default_schema(mut self, s: impl Into<String>) -> Self {
        self.default_schema = Some(s.into());
        self
    }

    pub(crate) fn principal_type(&self) -> PrincipalType {
        self.principal
            .as_ref()
            .map_or(PrincipalType::Unknown, |p| p.principal_type)
    }

    pub(crate) fn trust(&self) -> Trust {
        self.principal.as_ref().map_or(Trust::Weak, |p| p.trust)
    }
}

impl DbContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_env(mut self, env: impl Into<String>) -> Self {
        self.env = Some(env.into());
        self
    }
}

impl SessionContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tenant(mut self, t: impl Into<String>) -> Self {
        self.tenant = Some(t.into());
        self
    }

    pub fn with_application_name(mut self, a: impl Into<String>) -> Self {
        self.application_name = Some(a.into());
        self
    }

    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let json = r#"{"mode":"proxy","principal":{"id":"bot","type":"agent","trust":2,
            "attrs":{"max_refund":"200"}},"db":{"env":"prod"},
            "time":{"now_unix":1792600000,"tz":"Europe/Madrid","utc_offset_secs":7200},
            "ticket":{"id":"OPS-1"},"session":{"tenant":"t1"}}"#;
        let ctx: EvalContext = serde_json::from_str(json).unwrap();
        assert_eq!(ctx.mode, Some(HostMode::Proxy));
        let p = ctx.principal.as_ref().unwrap();
        assert_eq!(p.trust, Trust::Medium);
        assert_eq!(p.principal_type, PrincipalType::Agent);
        assert_eq!(ctx.trust(), Trust::Medium);
        assert!(!ctx.ticket.as_ref().unwrap().verified);
        let back: EvalContext =
            serde_json::from_str(&serde_json::to_string(&ctx).unwrap()).unwrap();
        assert_eq!(back, ctx);
        assert!(serde_json::from_str::<Trust>("\"high\"").is_err());
    }

    #[test]
    fn absent_principal_is_unknown_and_weak() {
        let ctx = EvalContext::new();
        assert_eq!(ctx.principal_type(), PrincipalType::Unknown);
        assert_eq!(ctx.trust(), Trust::Weak);
        assert!(Trust::Weak < Trust::Medium && Trust::Medium < Trust::Strong);
    }
}
