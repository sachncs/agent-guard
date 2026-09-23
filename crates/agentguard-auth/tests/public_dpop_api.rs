use agentguard_auth::{AsyncDpopReplayStore, AuthError, DpopVerifier};
use async_trait::async_trait;
use std::sync::Arc;

struct DownstreamReplayAdapter;

#[async_trait]
impl AsyncDpopReplayStore for DownstreamReplayAdapter {
    async fn check_and_record(&self, _jti: &[u8; 16]) -> agentguard_auth::error::Result<()> {
        Err(AuthError::Other("adapter reached".into()))
    }
}

#[tokio::test]
async fn async_replay_adapter_is_usable_from_the_public_crate_api() {
    let verifier = DpopVerifier::new_async(Arc::new(DownstreamReplayAdapter));

    assert!(matches!(
        verifier
            .verify_async("malformed", "token", "POST", "https://example.test/", "jkt")
            .await,
        Err(AuthError::DpopInvalid(_))
    ));
}
