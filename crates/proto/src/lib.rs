//! Types gRPC generes + conversions avec les types internes `sentinelle-common`.
//!
//! NON COMPILE depuis macOS (deps lourdes tonic/prost non telechargees ici).
//! A valider au 1er `cargo build` sous Windows : nom exact de `include_proto!`,
//! du module genere, et de `tonic_prost_build::compile_protos`.

pub mod v1 {
    tonic::include_proto!("sentinelle.v1");
}

use chrono::{DateTime, Utc};
use sentinelle_common::rules::Severity;
use sentinelle_common::{Alert, Event, EventKind};

// ---- Event ----

pub fn event_to_proto(e: &Event) -> v1::Event {
    v1::Event {
        ts: e.ts.to_rfc3339(),
        host: e.host.clone(),
        kind: kind_str(e.kind).to_string(),
        pid: e.pid,
        ppid: e.ppid,
        image: e.image.clone(),
        parent_image: e.parent_image.clone(),
        command_line: e.command_line.clone(),
        user: e.user.clone(),
        sha256: e.sha256.clone().unwrap_or_default(),
        dst_ip: e.dst_ip.clone(),
        dst_port: e.dst_port as u32,
        file_path: e.file_path.clone(),
        target_image: e.target_image.clone(),
        granted_access: e.granted_access.clone(),
        pipe_name: e.pipe_name.clone(),
    }
}

pub fn event_from_proto(p: v1::Event) -> Event {
    Event {
        ts: parse_ts(&p.ts),
        host: p.host,
        kind: kind_from_str(&p.kind),
        pid: p.pid,
        ppid: p.ppid,
        image: p.image,
        parent_image: p.parent_image,
        command_line: p.command_line,
        user: p.user,
        sha256: (!p.sha256.is_empty()).then_some(p.sha256),
        dst_ip: p.dst_ip,
        dst_port: p.dst_port as u16,
        file_path: p.file_path,
        target_image: p.target_image,
        granted_access: p.granted_access,
        pipe_name: p.pipe_name,
    }
}

// ---- Alert ----

pub fn alert_to_proto(a: &Alert) -> v1::Alert {
    v1::Alert {
        ts: a.ts.to_rfc3339(),
        host: a.host.clone(),
        rule_id: a.rule_id.clone(),
        title: a.title.clone(),
        description: a.description.clone(),
        severity: sev_str(a.severity).to_string(),
        attack: a.attack.clone(),
        score: a.score,
        event: Some(event_to_proto(&a.event)),
        ancestors: a.ancestors.clone(),
    }
}

pub fn alert_from_proto(p: v1::Alert) -> Alert {
    Alert {
        ts: parse_ts(&p.ts),
        host: p.host,
        rule_id: p.rule_id,
        title: p.title,
        description: p.description,
        severity: sev_from_str(&p.severity),
        attack: p.attack,
        score: p.score,
        event: p.event.map(event_from_proto).unwrap_or_else(|| {
            Event::process_start("", 0, 0, "", "")
        }),
        ancestors: p.ancestors,
    }
}

// ---- Telemetry helpers ----

pub fn tel_event(e: &Event) -> v1::Telemetry {
    v1::Telemetry {
        payload: Some(v1::telemetry::Payload::Event(event_to_proto(e))),
    }
}

pub fn tel_alert(a: &Alert) -> v1::Telemetry {
    v1::Telemetry {
        payload: Some(v1::telemetry::Payload::Alert(alert_to_proto(a))),
    }
}

// ---- enum <-> string ----

fn kind_str(k: EventKind) -> &'static str {
    match k {
        EventKind::ProcessStart => "process_start",
        EventKind::ProcessStop => "process_stop",
        EventKind::Network => "network",
        EventKind::FileWrite => "file_write",
        EventKind::ImageLoad => "image_load",
        EventKind::ProcessAccess => "process_access",
        EventKind::RemoteThread => "remote_thread",
        EventKind::NamedPipe => "named_pipe",
    }
}

fn kind_from_str(s: &str) -> EventKind {
    match s {
        "process_stop" => EventKind::ProcessStop,
        "network" => EventKind::Network,
        "file_write" => EventKind::FileWrite,
        "image_load" => EventKind::ImageLoad,
        "process_access" => EventKind::ProcessAccess,
        "remote_thread" => EventKind::RemoteThread,
        "named_pipe" => EventKind::NamedPipe,
        _ => EventKind::ProcessStart,
    }
}

fn sev_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn sev_from_str(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
