//! Sealed microphone WAL transitions.  Plain hashes are payload data, never
//! authority: only a consumed admission can mint an intent and only the writer
//! can return the matching terminal proof.
use anyhow::{ensure, Result};
use serde::Serialize;
use super::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use super::{EventFlags, HeaderBuilder};
use super::header::EventHeaderV2;
use crate::daemon::authorized_text_turn::SettledAuthorizedTextTurn;

const SCHEMA: u8 = 1;
const MAX_BYTES: usize = 768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MicOpenOutcome { Opened, Failed }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TurnCancelCause { User, Stale, Shutdown }

/// Produced by `MicConsentStore::consume_for_open`; it is move-only and has no
/// raw-ID constructor.  The writer consumes it to emit the durable intent.
pub(crate) struct MicOpenIntentAdmission { operation_id:String, home_binding:String, config_digest:String, permission_revision:u64, allow_once:bool, admitted_at_unix:i64 }
/// Returned only after the writer has durably accepted the intent.  It is the
/// sole authority that can form the corresponding terminal result.
pub(crate) struct MicOpenTerminalAuthority { operation_id:String, home_binding:String, config_digest:String, permission_revision:u64, allow_once:bool }
/// Produced only when the capture owner reports its actual start outcome.
pub(crate) struct MicOpenResultAdmission { operation_id:String, outcome:MicOpenOutcome, error_code:Option<String>, completed_at_unix:i64 }
pub(crate) struct TurnCancelAdmission { turn_id:String, cause:TurnCancelCause, cancelled_at_unix:i64 }

#[derive(Serialize)] #[serde(deny_unknown_fields)]
struct IntentPayload { schema_version:u8, operation_id:String, config_digest:String, permission_revision:u64, admitted_at_unix:i64 }
#[derive(Serialize)] #[serde(deny_unknown_fields)]
struct ResultPayload { schema_version:u8, operation_id:String, outcome:&'static str, error_code:Option<String>, completed_at_unix:i64 }
#[derive(Serialize)] #[serde(deny_unknown_fields)]
struct CancelPayload { schema_version:u8, turn_id:String, cause:&'static str, cancelled_at_unix:i64 }

impl MicOpenIntentAdmission {
    pub(crate) fn from_consumed(admission: crate::permissions::microphone::MicOpenAdmission) -> Self { let (operation_id,home_binding,config_digest,permission_revision,allow_once,admitted_at_unix)=admission.into_parts(); Self { operation_id, home_binding, config_digest, permission_revision, allow_once, admitted_at_unix } }
    pub(crate) fn into_frame(self)->Result<(EventHeaderV2,Vec<u8>,MicOpenTerminalAuthority)> { ensure!(hex64(&self.operation_id)&&hex64(&self.home_binding)&&hex64(&self.config_digest),"sealed microphone intent binding"); let payload=serde_json::to_vec(&IntentPayload{schema_version:SCHEMA,operation_id:self.operation_id.clone(),config_digest:self.config_digest.clone(),permission_revision:self.permission_revision,admitted_at_unix:self.admitted_at_unix})?; ensure!(payload.len()<=MAX_BYTES,"microphone intent bound"); let header=HeaderBuilder::new(EVENT_TYPE_EXTENDED,&payload).event_subtype(ExtendedSubtype::MicrophoneOpenIntent as u8).flags(EventFlags::SYNTHETIC).build(); Ok((header,payload,MicOpenTerminalAuthority{operation_id:self.operation_id,home_binding:self.home_binding,config_digest:self.config_digest,permission_revision:self.permission_revision,allow_once:self.allow_once})) }
}
impl MicOpenTerminalAuthority {
    /// Retains the consumed admission's private binding through the durable
    /// intent/permit boundary. It cannot mint a fresh capability or terminal.
    pub(crate) fn revalidate_device_open(&self, store:&crate::permissions::microphone::MicConsentStore)->Result<()> { store.revalidate_terminal_for_device_open(&self.home_binding,&self.config_digest,self.permission_revision,self.allow_once).map_err(Into::into) }
    /// The capture owner calls this only after the concrete `CpalCaptureSession::start`
    /// attempt has returned. Consumes the authority, preventing duplicate terminals.
    pub(crate) fn complete(self,outcome:MicOpenOutcome,error_code:Option<&str>,completed_at_unix:i64)->Result<MicOpenResultAdmission> { if matches!(outcome,MicOpenOutcome::Opened) {ensure!(error_code.is_none(),"opened microphone cannot carry an error")} else {ensure!(error_code.is_some(),"failed microphone requires typed error")}; if let Some(code)=error_code {ensure!(valid_code(code),"invalid microphone error code")}; Ok(MicOpenResultAdmission{operation_id:self.operation_id,outcome,error_code:error_code.map(str::to_owned),completed_at_unix}) }
}
impl MicOpenResultAdmission { pub(crate) fn into_frame(self)->Result<(EventHeaderV2,Vec<u8>)> { let outcome=match self.outcome {MicOpenOutcome::Opened=>"opened",MicOpenOutcome::Failed=>"failed"}; let payload=serde_json::to_vec(&ResultPayload{schema_version:SCHEMA,operation_id:self.operation_id,outcome,error_code:self.error_code,completed_at_unix:self.completed_at_unix})?; ensure!(payload.len()<=MAX_BYTES,"microphone result bound"); Ok((HeaderBuilder::new(EVENT_TYPE_EXTENDED,&payload).event_subtype(ExtendedSubtype::MicrophoneOpenResult as u8).flags(EventFlags::SYNTHETIC).build(),payload)) } }
impl TurnCancelAdmission {
    /// A cancellation receipt is possible only when the stream owner consumed a
    /// persisted-cursor terminal and minted its private cancellation proof.
    /// A Complete/Failed race returns no proof and therefore cannot write 0x3A.
    pub(crate) fn from_settled_turn(
        settled: SettledAuthorizedTextTurn,
        cause: TurnCancelCause,
        cancelled_at_unix: i64,
    ) -> Result<Self> {
        let proof = settled.into_cancel_proof()
            .ok_or_else(|| anyhow::anyhow!("authorized text turn did not settle as cancelled"))?;
        let turn_id = proof.into_turn_id_sha256();
        ensure!(hex64(&turn_id), "settled turn binding");
        Ok(Self { turn_id, cause, cancelled_at_unix })
    }
}
impl TurnCancelAdmission { pub(crate) fn into_frame(self)->Result<(EventHeaderV2,Vec<u8>)>{let cause=match self.cause{TurnCancelCause::User=>"user",TurnCancelCause::Stale=>"stale",TurnCancelCause::Shutdown=>"shutdown"};let payload=serde_json::to_vec(&CancelPayload{schema_version:SCHEMA,turn_id:self.turn_id,cause,cancelled_at_unix:self.cancelled_at_unix})?;ensure!(payload.len()<=MAX_BYTES,"turn cancellation bound");Ok((HeaderBuilder::new(EVENT_TYPE_EXTENDED,&payload).event_subtype(ExtendedSubtype::RealtimeTurnCancel as u8).flags(EventFlags::SYNTHETIC).build(),payload))} }
fn hex64(v:&str)->bool{v.len()==64&&v.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())} fn valid_code(v:&str)->bool{v.len()<=64&&v.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'_')}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::microphone::{MicConsentStore, MicDecision, MicPreflight};
    use tempfile::tempdir;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn consumed_admission_forms_one_sealed_intent_then_terminal_result() {
        let home = tempdir().expect("temporary home");
        let mut store = MicConsentStore::open(home.path()).expect("open consent store");
        let MicPreflight::ConfirmationRequired { challenge } = store
            .preflight(DIGEST, 10)
            .expect("preflight") else { panic!("fresh store requires confirmation") };
        let capability = store.decide(challenge, MicDecision::AllowOnce, 11)
            .expect("decision")
            .expect("allow-once capability");
        let admission = store.consume_for_open(capability, DIGEST, 12)
            .expect("consume exactly once");

        let intent = MicOpenIntentAdmission::from_consumed(admission);
        let (header, _payload, terminal) = intent.into_frame().expect("sealed intent frame");
        assert_eq!(header.event_subtype, ExtendedSubtype::MicrophoneOpenIntent as u8);
        let other_home = tempdir().expect("independent home");
        let other_store = MicConsentStore::open(other_home.path()).expect("open other store");
        assert!(terminal.revalidate_device_open(&other_store).is_err(),
            "a matching revision at another canonical home is not this admission");
        terminal.revalidate_device_open(&store)
            .expect("terminal retains only a read-only pre-open binding");
        let result = terminal.complete(MicOpenOutcome::Opened, None, 13)
            .expect("only terminal authority can form opened result");
        let (header, _payload) = result.into_frame().expect("sealed result frame");
        assert_eq!(header.event_subtype, ExtendedSubtype::MicrophoneOpenResult as u8);
    }
}
