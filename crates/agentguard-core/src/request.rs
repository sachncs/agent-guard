//! Agent authorization requests and a builder.

use crate::action::AgentAction;
use crate::context::AgentContext;
use crate::error::{Error, Result};
use crate::observability::TraceContext;
use crate::principal::Principal;
use crate::resource::Resource;
use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid, Request};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A full authorization request: principal + action + resource + context.
///
/// Construct via [`AgentRequest::new`] for a quick request, or
/// [`AgentRequestBuilder`] for type-safe incremental construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct AgentRequest {
    pub principal: Principal,
    pub action: AgentAction,
    pub resource: Resource,
    pub context: AgentContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional W3C Trace Context (parsed from `traceparent` header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceContext>,
    /// Tenant ID for multi-tenant deployments. Propagated through to
    /// `DecisionRecord` so per-tenant SAR queries, blast-radius
    /// analyses, and audit log scans can scope by tenant.
    ///
    /// No format constraint is enforced here; the caller decides
    /// (UUID, slug, email, etc). `with_tenant_id` trims whitespace
    /// and converts empty strings to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl AgentRequest {
    /// Construct a request with a fresh UUID v7 request id.
    pub fn new(
        principal: Principal,
        action: AgentAction,
        resource: Resource,
        context: AgentContext,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
            request_id: Some(uuid::Uuid::now_v7().to_string()),
            trace: None,
            tenant_id: None,
        }
    }

    /// Override the auto-generated request id.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Attach a W3C Trace Context.
    pub fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = Some(trace);
        self
    }

    /// Set the tenant ID. Whitespace is trimmed; empty/whitespace-only
    /// values become `None`. No other format constraint.
    pub fn with_tenant_id(mut self, tid: impl Into<String>) -> Self {
        let s = tid.into();
        self.tenant_id = if s.trim().is_empty() {
            None
        } else {
            Some(s.trim().to_string())
        };
        self
    }

    /// Convert to a `cedar_policy::Request`. `schema` is used to construct
    /// a typed context (validates context shape per action) when available.
    ///
    /// # Errors
    /// Returns `Error::InvalidPrincipal` / `Error::InvalidResource` if
    /// the principal type or resource type name is not a valid Cedar
    /// identifier. Returns `Error::InvalidContext` if the context cannot
    /// be parsed against the schema.
    pub fn to_cedar_request(&self, schema: Option<&cedar_policy::Schema>) -> Result<Request> {
        let principal_eid = EntityId::new(&**self.principal.id());
        let principal_etype =
            EntityTypeName::from_str(self.principal.entity_type()).map_err(|e| {
                Error::InvalidPrincipal(format!("{}: {}", self.principal.entity_type(), e))
            })?;
        let principal_uid = EntityUid::from_type_name_and_id(principal_etype, principal_eid);

        let action_eid = EntityId::new(self.action.action_id());
        let action_etype = EntityTypeName::from_str("Action")
            .map_err(|e| Error::InvalidPrincipal(format!("Action: {}", e)))?;
        let action_uid = EntityUid::from_type_name_and_id(action_etype, action_eid);

        let resource_eid = EntityId::new(&self.resource.uid);
        let resource_etype = EntityTypeName::from_str(&self.resource.entity_type)
            .map_err(|e| Error::InvalidResource(format!("{}: {}", self.resource.entity_type, e)))?;
        let resource_uid = EntityUid::from_type_name_and_id(resource_etype, resource_eid);

        // Build context JSON.
        let mut ctx_map = self.context.to_json_object();
        let ctx_json = serde_json::Value::Object(std::mem::take(&mut ctx_map));

        let context = match schema {
            Some(s) => {
                let json_str = serde_json::to_string(&ctx_json)?;
                Context::from_json_str(&json_str, Some((s, &action_uid)))
                    .map_err(|e| Error::InvalidContext(e.to_string()))?
            }
            None => Context::from_json_str(&serde_json::to_string(&ctx_json)?, None)
                .map_err(|e| Error::InvalidContext(e.to_string()))?,
        };

        let req = Request::new(principal_uid, action_uid, resource_uid, context, schema)
            .map_err(|e| Error::InvalidContext(e.to_string()))?;

        Ok(req)
    }
}

/// Builder for [`AgentRequest`] with type-safe setters.
///
/// # Examples
/// ```
/// use agentguard_core::{AgentRequestBuilder, Principal, AgentAction, Resource, AgentContext};
/// let req = AgentRequestBuilder::new(Principal::user("alice"))
///     .action(AgentAction::tool("send_email"))
///     .resource(Resource::new("Mailbox", "alice@acme"))
///     .context(AgentContext::new())
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AgentRequestBuilder {
    principal: Principal,
    action: Option<AgentAction>,
    resource: Option<Resource>,
    context: AgentContext,
    request_id: Option<String>,
    trace: Option<TraceContext>,
    tenant_id: Option<String>,
}

impl AgentRequestBuilder {
    /// Start building a request for the given principal.
    pub fn new(principal: impl Into<Principal>) -> Self {
        Self {
            principal: principal.into(),
            action: None,
            resource: None,
            context: AgentContext::new(),
            request_id: None,
            trace: None,
            tenant_id: None,
        }
    }

    /// Set the action (tool call).
    pub fn action(mut self, a: impl Into<AgentAction>) -> Self {
        self.action = Some(a.into());
        self
    }

    /// Set the resource.
    pub fn resource(mut self, r: impl Into<Resource>) -> Self {
        self.resource = Some(r.into());
        self
    }

    /// Set the context.
    pub fn context(mut self, c: impl Into<AgentContext>) -> Self {
        self.context = c.into();
        self
    }

    /// Override the auto-generated request id.
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Attach a W3C Trace Context.
    pub fn trace(mut self, trace: TraceContext) -> Self {
        self.trace = Some(trace);
        self
    }

    /// Attach a trace by parsing a `traceparent` string.
    ///
    /// # Errors
    /// Returns `Error::Other` (or a parse error) if the traceparent string
    /// is malformed.
    pub fn traceparent(mut self, tp: &str) -> Result<Self> {
        let trace: TraceContext = tp.parse()?;
        self.trace = Some(trace);
        Ok(self)
    }

    /// Set the tenant ID. Whitespace is trimmed; empty/whitespace-only
    /// values become `None`. No other format constraint.
    pub fn tenant_id(mut self, tid: impl Into<String>) -> Self {
        let s = tid.into();
        self.tenant_id = if s.trim().is_empty() {
            None
        } else {
            Some(s.trim().to_string())
        };
        self
    }

    /// Finalize the request. Returns an error if action or resource is missing.
    pub fn build(self) -> Result<AgentRequest> {
        let action = self
            .action
            .ok_or_else(|| Error::InvalidPrincipal("action is required".into()))?;
        let resource = self
            .resource
            .ok_or_else(|| Error::InvalidResource("resource is required".into()))?;
        let mut req = AgentRequest::new(self.principal, action, resource, self.context);
        if let Some(id) = self.request_id {
            req.request_id = Some(id);
        }
        req.trace = self.trace;
        req.tenant_id = self.tenant_id;
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentAction;

    #[test]
    fn builder_sets_all_fields() {
        let req = AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .context(AgentContext::new().with_arg("to", "[email protected]"))
            .build()
            .unwrap();
        assert_eq!(format!("{}", req.principal), "User::\"alice\"");
        assert_eq!(format!("{}", req.action), "Action::\"ToolCall::send_email\"");
        assert_eq!(format!("{}", req.resource), "Mailbox::\"alice@acme\"");
        assert!(req.request_id.is_some());
    }

    #[test]
    fn builder_requires_action() {
        let res = AgentRequestBuilder::new(Principal::user("alice"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .build();
        assert!(res.is_err());
    }

    #[test]
    fn builder_requires_resource() {
        let res = AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .build();
        assert!(res.is_err());
    }

    #[test]
    fn new_auto_assigns_request_id() {
        let req = AgentRequest::new(
            Principal::user("alice"),
            AgentAction::tool("send_email"),
            Resource::new("Mailbox", "alice@acme"),
            AgentContext::new(),
        );
        assert!(req.request_id.is_some());
    }

    #[test]
    fn tenant_id_round_trips() {
        let req = AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .tenant_id("acme-corp")
            .build()
            .unwrap();
        assert_eq!(req.tenant_id.as_deref(), Some("acme-corp"));

        // Whitespace-only becomes None.
        let req = AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .tenant_id("   ")
            .build()
            .unwrap();
        assert_eq!(req.tenant_id, None);

        // Surrounding whitespace is trimmed.
        let req = AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .tenant_id("  acme-corp  ")
            .build()
            .unwrap();
        assert_eq!(req.tenant_id.as_deref(), Some("acme-corp"));

        // Serde round-trips through JSON.
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tenant_id.as_deref(), Some("acme-corp"));
    }
}
