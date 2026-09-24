//! Process-wide metrics counters and `tracing` bootstrap (I3, I11).

use std::sync::atomic::{AtomicU64, Ordering};

static COMMANDS_TOTAL: AtomicU64 = AtomicU64::new(0);
static COMMANDS_EXECUTED: AtomicU64 = AtomicU64::new(0);
static POLICY_DENIES: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_REJECTS: AtomicU64 = AtomicU64::new(0);
static VERSION_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static EXECUTION_FAILURES: AtomicU64 = AtomicU64::new(0);
static METRICS_SCRAPES: AtomicU64 = AtomicU64::new(0);

/// Initialize the global `tracing` subscriber from `RUST_LOG` (default
/// `info`). Safe to call more than once; later calls are no-ops.
///
/// With `--features otel` (I4), also installs an OpenTelemetry layer
/// (stdout span exporter; swap for OTLP via OTEL env vars + a processor).
///
/// Called from `run_from_config` on Unix. On non-Unix builds the accept
/// loop never starts, so this stays uncalled (silence `dead_code` there).
#[cfg_attr(not(unix), allow(dead_code))]
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(all(feature = "otel", unix))]
    {
        init_otel_layered(filter);
        return;
    }

    #[cfg(not(all(feature = "otel", unix)))]
    {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    }
}

#[cfg(all(feature = "otel", unix))]
fn init_otel_layered(filter: tracing_subscriber::EnvFilter) {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::layer::SubscriberExt as _;

    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
        .build();
    let tracer = provider.tracer("tpt-privd");
    opentelemetry::global::set_tracer_provider(provider.clone());

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init();

    tracing::info!("tracing initialized with OpenTelemetry stdout exporter (feature=otel)");
}

pub(crate) fn record_total() {
    COMMANDS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_executed() {
    COMMANDS_EXECUTED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_policy_deny() {
    POLICY_DENIES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_transport_reject() {
    TRANSPORT_REJECTS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_version_mismatch() {
    VERSION_MISMATCHES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_execution_failure() {
    EXECUTION_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_metrics_scrape() {
    METRICS_SCRAPES.fetch_add(1, Ordering::Relaxed);
}

/// Prometheus text exposition for built-in `CommandKind::METRICS` (I3).
///
/// Counters are process-wide; each scrape is itself counted (after the
/// snapshot is taken, so the scrape total does not include the current
/// sample's self-count until the next scrape).
#[must_use]
pub fn prometheus_text() -> String {
    let total = COMMANDS_TOTAL.load(Ordering::Relaxed);
    let executed = COMMANDS_EXECUTED.load(Ordering::Relaxed);
    let denies = POLICY_DENIES.load(Ordering::Relaxed);
    let rejects = TRANSPORT_REJECTS.load(Ordering::Relaxed);
    let version = VERSION_MISMATCHES.load(Ordering::Relaxed);
    let exec_fail = EXECUTION_FAILURES.load(Ordering::Relaxed);
    let scrapes = METRICS_SCRAPES.load(Ordering::Relaxed);

    format!(
        "# HELP tpt_privd_commands_total Total decoded commands received.\n\
         # TYPE tpt_privd_commands_total counter\n\
         tpt_privd_commands_total {total}\n\
         # HELP tpt_privd_commands_executed_total Commands that reached Executed.\n\
         # TYPE tpt_privd_commands_executed_total counter\n\
         tpt_privd_commands_executed_total {executed}\n\
         # HELP tpt_privd_policy_denies_total Commands denied by policy.\n\
         # TYPE tpt_privd_policy_denies_total counter\n\
         tpt_privd_policy_denies_total {denies}\n\
         # HELP tpt_privd_transport_rejects_total Undecodable frames audited as rejects.\n\
         # TYPE tpt_privd_transport_rejects_total counter\n\
         tpt_privd_transport_rejects_total {rejects}\n\
         # HELP tpt_privd_version_mismatches_total Commands with unsupported envelope version.\n\
         # TYPE tpt_privd_version_mismatches_total counter\n\
         tpt_privd_version_mismatches_total {version}\n\
         # HELP tpt_privd_execution_failures_total Commands that failed execution.\n\
         # TYPE tpt_privd_execution_failures_total counter\n\
         tpt_privd_execution_failures_total {exec_fail}\n\
         # HELP tpt_privd_metrics_scrapes_total METRICS scrapes served.\n\
         # TYPE tpt_privd_metrics_scrapes_total counter\n\
         tpt_privd_metrics_scrapes_total {scrapes}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_text_has_metric_names() {
        let text = prometheus_text();
        assert!(text.contains("tpt_privd_commands_total"));
        assert!(text.contains("# TYPE tpt_privd_policy_denies_total counter"));
    }

    #[test]
    fn counters_increment() {
        let before = COMMANDS_TOTAL.load(Ordering::Relaxed);
        record_total();
        assert_eq!(COMMANDS_TOTAL.load(Ordering::Relaxed), before + 1);
    }
}
