/// Audit macro for logging security and authentication events.
///
/// This macro wraps `tracing::info!` and automatically adds `audit=true`
/// and `auditType="authentication"` metadata to the log event.
///
/// # Examples
///
/// ```
/// audit!("User {} logged in", user_id);
/// ```
#[macro_export]
macro_rules! audit {
    ($($arg:tt)+) => {
        tracing::info!(
            audit = true,
            auditType = "authentication",
            $($arg)+
        )
    };
}
