use serde::{Deserialize, Serialize};
use crate::shared::utils::date_util::{DateTime, DateUtil};
use uuid::Uuid;
use bson::oid::ObjectId;

// Session model for tracking active sessions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSession {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub session_id: String,     // UUID as string
    pub user_id: String,        // User UUID
    pub token_jti: String,      // JWT ID for token invalidation
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime,
    pub expires_at: DateTime,
    pub is_active: bool,
}

impl UserSession {
    pub fn new(user_id: String, token_jti: String, expires_at: DateTime) -> Self {
        Self {
            id: None,
            session_id: Uuid::new_v4().to_string(),
            user_id,
            token_jti,
            ip_address: None,
            user_agent: None,
            created_at: DateUtil::now(),
            expires_at,
            is_active: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        DateUtil::now() >= self.expires_at
    }

    pub fn invalidate(&mut self) {
        self.is_active = false;
    }

    pub fn set_client_info(&mut self, ip_address: Option<String>, user_agent: Option<String>) {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_session() {
        let user_id = Uuid::new_v4().to_string();
        let token_jti = Uuid::new_v4().to_string();
        let expires_at = DateUtil::add_duration(&DateUtil::now(), DateUtil::hours(24)).unwrap();

        let mut session = UserSession::new(user_id.clone(), token_jti.clone(), expires_at);

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.token_jti, token_jti);
        assert!(session.is_active);
        assert!(!session.is_expired());

        session.invalidate();
        assert!(!session.is_active);
    }
} 