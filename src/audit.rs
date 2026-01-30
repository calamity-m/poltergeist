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
        $crate::middleware::with_request_info(|ctx| {
            tracing::info!(
                audit = true,
                auditType = "authentication",
                endpoint = %ctx.endpoint,
                host = %ctx.host,
                httpMethod = %ctx.method,
                $($arg)+
            )
        })
    };
}
