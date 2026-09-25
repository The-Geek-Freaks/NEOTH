//! Receipt-bound repair of one retained Paperless installation.
//!
//! The install receipt is ownership authority. Compose labels are only an
//! additional conflict fence and are never used to adopt an unknown container.

use super::*;

const REPAIR_JOURNAL_NAME: &str = ".neoth-paperless-repair.v1.json";
const ROTATION_JOURNAL_NAME: &str = ".neoth-paperless-generation-rotation.v1.json";
const GENERATION_AUTH_NAME: &str = ".neoth-paperless-generation-auth.v1.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PaperlessRepairAction { Healthy, Started, Recreated }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PaperlessRepairServiceReceipt { pub(crate) service:String, pub(crate) action:PaperlessRepairAction, pub(crate) prior_id:String, pub(crate) current_id:String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PaperlessRepairReceipt { pub(crate) schema_version:u8, pub(crate) operation:String, pub(crate) project:String, pub(crate) volume_set_id:String, pub(crate) services:Vec<PaperlessRepairServiceReceipt> }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RepairPhase { Prepared, StartDispatched, CreateDispatched, Bound, ReceiptCommitDispatched, Complete, Held }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairMember { service:String, prior_id:String, image_id:String, action:PaperlessRepairAction, #[serde(default)] current_id:Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaperlessRepairJournal { schema_version:u8, operation:String, phase:RepairPhase, project:String, volume_set_id:String, install_receipt_sha256:String, before_receipt_bytes:Vec<u8>, #[serde(default)] after_receipt_bytes:Option<Vec<u8>>, members:Vec<RepairMember>, #[serde(default)] effect_service:Option<String> }

struct RepairReadinessContext<'a, R> {
    home: &'a Path,
    credentials: &'a Credentials,
    readiness: &'a R,
}

pub(crate) async fn repair_at(home:&Path, credentials:&Credentials)->Result<PaperlessRepairReceipt,LifecycleError>{ repair_at_with_readiness(home,credentials,&mut DockerExecutor,&ConfiguredReadiness).await }

/// Production I/O with injectable retained-compose and readiness boundaries.
pub(super) async fn repair_at_with_readiness<E:RetainedComposeExecutor,R:ReadinessVerifier>(home:&Path,credentials:&Credentials,executor:&mut E,readiness:&R)->Result<PaperlessRepairReceipt,LifecycleError>{
 let root_path=crate::config::InstancePaths::for_home(home).paperless_root;
 match paperless_staging::inspect_at(&root_path).status { PaperlessStagingStatus::PreparedPinned|PaperlessStagingStatus::AlreadyPrepared=>{},PaperlessStagingStatus::NotPrepared=>return Err(LifecycleError::NotPrepared),PaperlessStagingStatus::UnownedOrMismatch=>return Err(LifecycleError::UnownedOrMismatch) }
 let owned=paperless_staging::open_owned_root_at(&root_path).map_err(|_|LifecycleError::UnownedOrMismatch)?;let mut binding=read_binding(&owned)?;reject_legacy_state(&owned)?;compose_environment(&binding)?;validate_credentials_origin(credentials,&binding.origin)?;if valid_token(credentials.paperless_token.as_ref()).is_none(){return Err(LifecycleError::Bootstrap("paperless_repair_token_required"));}
 let _launch=acquire_launch_guard(&owned,&binding)?;let _lock=paperless_operation_lock::acquire(&owned,OsStr::new(OPERATIONS_LOCK_NAME)).map_err(map_operation_lock_error)?;refuse_repair_custody(&owned)?;
 let (receipt_bytes,receipt)=read_install_receipt_with_bytes(&owned)?;validate_install_receipt(&receipt,&root_path)?;let volume_set_id=receipt.volume_set_id.clone().ok_or(LifecycleError::Receipt)?;let engine=select_local_engine(executor,&owned).await?;binding.volume_set_id=preflight_existing_volumes(executor,&engine,&receipt.project,&owned,&binding).await?;if binding.volume_set_id.as_deref()!=Some(volume_set_id.as_str()){return Err(LifecycleError::UnownedOrMismatch);}verify_receipt_images(executor,&engine,&owned,&binding,&root_path,&receipt).await?;
 let readiness_context=RepairReadinessContext{home,credentials,readiness};
 if let Some(journal)=read_repair_journal(&owned)? { validate_repair_journal(&journal,&receipt,&receipt_bytes,&root_path)?;return resume_repair(&readiness_context,executor,&engine,&owned,&binding,&receipt,journal).await; }
 let members=classify_all(executor,&engine,&owned,&binding,&receipt).await?;
 if members.iter().all(|item|item.action==PaperlessRepairAction::Healthy){require_ready(home,credentials,readiness,&binding).await?;return repair_receipt(&receipt.project,&volume_set_id,&members);}
 let journal=PaperlessRepairJournal{schema_version:1,operation:"paperless.repair".into(),phase:RepairPhase::Prepared,project:receipt.project.clone(),volume_set_id,install_receipt_sha256:digest(&receipt_bytes),before_receipt_bytes:receipt_bytes,after_receipt_bytes:None,members,effect_service:None};write_repair_journal_create_new(&owned,&journal)?;resume_repair(&readiness_context,executor,&engine,&owned,&binding,&receipt,journal).await
}

async fn resume_repair<E:RetainedComposeExecutor,R:ReadinessVerifier>(context:&RepairReadinessContext<'_,R>,executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,receipt:&StoredPaperlessInstallReceipt,mut journal:PaperlessRepairJournal)->Result<PaperlessRepairReceipt,LifecycleError>{
 let home=context.home;let credentials=context.credentials;let readiness=context.readiness;
 if journal.phase==RepairPhase::Held{return Err(LifecycleError::Command("paperless_repair_held"));}
 if journal.phase==RepairPhase::Complete{return finish_committed_repair(context,executor,engine,root,binding,receipt,&journal).await;}
 if journal.phase==RepairPhase::ReceiptCommitDispatched {commit_receipt_exact(root,&journal)?;journal.phase=RepairPhase::Complete;write_repair_journal(root,&journal)?;return finish_committed_repair(context,executor,engine,root,binding,receipt,&journal).await;}
 if journal.phase==RepairPhase::CreateDispatched {hold(root,&mut journal)?;return Err(LifecycleError::Command("paperless_repair_create_outcome_ambiguous"));}
 if journal.phase==RepairPhase::StartDispatched {let service=journal.effect_service.clone().ok_or(LifecycleError::Receipt)?;let member=journal.members.iter().find(|item|item.service==service).ok_or(LifecycleError::Receipt)?;if !exact_container_present(executor,engine,&member.prior_id,root,binding).await?{hold(root,&mut journal)?;return Err(LifecycleError::Command("paperless_repair_start_id_missing"));}let raw=inspect(executor,engine,root,binding,&member.prior_id).await?;if verify_container(&image_for(receipt,&service)?,&journal.project,binding.port,&raw.stdout).is_err(){executor.run(&engine.docker("container",&["start",&member.prior_id]),&root.display).await?;}mark_started(executor,engine,root,binding,receipt,&mut journal,&service).await?;}
 while let Some(index)=journal.members.iter().position(|item|item.current_id.is_none()) {let service=journal.members[index].service.clone();match journal.members[index].action {PaperlessRepairAction::Healthy=>{journal.members[index].current_id=Some(journal.members[index].prior_id.clone());write_repair_journal(root,&journal)?;},PaperlessRepairAction::Started=>{let id=journal.members[index].prior_id.clone();journal.phase=RepairPhase::StartDispatched;journal.effect_service=Some(service.clone());write_repair_journal(root,&journal)?;let outcome=executor.run(&engine.docker("container",&["start",&id]),&root.display).await;if outcome.is_err()&&!exact_container_present(executor,engine,&id,root,binding).await?{hold(root,&mut journal)?;return Err(LifecycleError::Command("paperless_repair_start_outcome_ambiguous"));}mark_started(executor,engine,root,binding,receipt,&mut journal,&service).await?;},PaperlessRepairAction::Recreated=>{journal.phase=RepairPhase::CreateDispatched;journal.effect_service=Some(service.clone());write_repair_journal(root,&journal)?;if executor.run_retained(&engine.compose(&journal.project,&["up","-d","--no-build","--pull","never",&service]),root,binding).await.is_err(){hold(root,&mut journal)?;return Err(LifecycleError::Command("paperless_repair_create_outcome_ambiguous"));}let raw_id=executor.run_retained(&engine.compose(&journal.project,&["ps","-q",&service]),root,binding).await?.stdout;let id=exact_identifier(&raw_id).ok_or(LifecycleError::Command("paperless_repair_created_id_missing"))?;let raw=inspect(executor,engine,root,binding,&id).await?;let observed=verify_container(&image_for(receipt,&service)?,&journal.project,binding.port,&raw.stdout)?;if observed.id!=id||id==journal.members[index].prior_id{hold(root,&mut journal)?;return Err(LifecycleError::Command("paperless_repair_created_id_invalid"));}journal.members[index].current_id=Some(id);journal.phase=RepairPhase::Bound;journal.effect_service=None;write_repair_journal(root,&journal)?;}}}
 journal.phase=RepairPhase::Bound;journal.effect_service=None;if journal.after_receipt_bytes.is_none(){journal.after_receipt_bytes=Some(replacement_receipt_bytes(&journal)?);write_repair_journal(root,&journal)?;}revalidate_bound_resources(executor,engine,root,binding,receipt,&journal).await?;require_ready(home,credentials,readiness,binding).await?;journal.phase=RepairPhase::ReceiptCommitDispatched;write_repair_journal(root,&journal)?;commit_receipt_exact(root,&journal)?;journal.phase=RepairPhase::Complete;write_repair_journal(root,&journal)?;finish_committed_repair(context,executor,engine,root,binding,receipt,&journal).await
}
async fn mark_started<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,receipt:&StoredPaperlessInstallReceipt,journal:&mut PaperlessRepairJournal,service:&str)->Result<(),LifecycleError>{let index=journal.members.iter().position(|item|item.service==service).ok_or(LifecycleError::Receipt)?;let id=journal.members[index].prior_id.clone();let raw=inspect(executor,engine,root,binding,&id).await?;let observed=verify_container(&image_for(receipt,service)?,&journal.project,binding.port,&raw.stdout)?;if observed.id!=id{hold(root,journal)?;return Err(LifecycleError::Command("paperless_repair_start_id_changed"));}journal.members[index].current_id=Some(id);journal.phase=RepairPhase::Prepared;journal.effect_service=None;write_repair_journal(root,journal)}
async fn finish_committed_repair<E:ComposeExecutor,R:ReadinessVerifier>(context:&RepairReadinessContext<'_,R>,executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,receipt:&StoredPaperlessInstallReceipt,journal:&PaperlessRepairJournal)->Result<PaperlessRepairReceipt,LifecycleError>{commit_receipt_exact(root,journal)?;revalidate_bound_resources(executor,engine,root,binding,receipt,journal).await?;require_ready(context.home,context.credentials,context.readiness,binding).await?;let output=repair_receipt(&journal.project,&journal.volume_set_id,&journal.members)?;remove_repair_journal(root)?;Ok(output)}

async fn classify_all<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,receipt:&StoredPaperlessInstallReceipt)->Result<Vec<RepairMember>,LifecycleError>{let mut out=Vec::with_capacity(receipt.containers.len());for stored in &receipt.containers {let claimants=service_claimants(executor,engine,root,binding,&receipt.project,&stored.service).await?;let present=exact_container_present(executor,engine,&stored.id,root,binding).await?;if present {if claimants.len()!=1||claimants.first().map(String::as_str)!=Some(stored.id.as_str()){return Err(LifecycleError::UnownedOrMismatch);}let raw=inspect(executor,engine,root,binding,&stored.id).await?;verify_original_container(stored,&receipt.project,binding.port,&raw.stdout)?;let actual:DockerContainer=serde_json::from_str(&raw.stdout).map_err(|_|LifecycleError::Receipt)?;let action=if actual.state.running{PaperlessRepairAction::Healthy}else{PaperlessRepairAction::Started};out.push(RepairMember{service:stored.service.clone(),prior_id:stored.id.clone(),image_id:stored.image_id.clone(),action,current_id:(action==PaperlessRepairAction::Healthy).then(||stored.id.clone())});}else{if !claimants.is_empty(){return Err(LifecycleError::UnownedOrMismatch);}out.push(RepairMember{service:stored.service.clone(),prior_id:stored.id.clone(),image_id:stored.image_id.clone(),action:PaperlessRepairAction::Recreated,current_id:None});}}if out.len()!=3{return Err(LifecycleError::Receipt);}Ok(out)}
async fn service_claimants<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,project:&str,service:&str)->Result<Vec<String>,LifecycleError>{ensure_stage(root,binding)?;let result=executor.run(&engine.docker("container",&["ls","--all","--filter",&format!("label=com.docker.compose.project={project}"),"--filter",&format!("label=com.docker.compose.service={service}"),"--no-trunc","--format","{{.ID}}"]),&root.display).await?;ensure_stage(root,binding)?;let mut ids=Vec::new();for line in result.stdout.lines(){let id=line.trim();if !exact_container_id(id){return Err(LifecycleError::UnownedOrMismatch);}ids.push(id.to_owned());}ids.sort();ids.dedup();Ok(ids)}
async fn inspect<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,id:&str)->Result<CommandOutput,LifecycleError>{ensure_stage(root,binding)?;let result=executor.run(&engine.docker("container",&["inspect",id,"--format",CONTAINER_INSPECT_TEMPLATE]),&root.display).await?;ensure_stage(root,binding)?;Ok(result)}
fn image_for(receipt:&StoredPaperlessInstallReceipt,service:&str)->Result<VerifiedImage,LifecycleError>{let stored=receipt.images.iter().find(|item|item.service==service).ok_or(LifecycleError::Receipt)?;let expected=expected_images()?.into_iter().find(|item|item.service==service).ok_or(LifecycleError::Receipt)?;Ok(VerifiedImage{service:expected.service,reference:expected.reference,repo_digest:stored.repo_digest.clone(),config_id:stored.config_id.clone(),os:stored.os.clone(),architecture:stored.architecture.clone()})}
async fn verify_receipt_images<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,root_path:&Path,receipt:&StoredPaperlessInstallReceipt)->Result<(),LifecycleError>{for expected in expected_images()?{let stored=receipt.images.iter().find(|item|item.service==expected.service).ok_or(LifecycleError::Receipt)?;if stored.reference!=expected.reference||stored.repo_digest!=expected.repo_digest{return Err(LifecycleError::Image("paperless_repair_version_drift"));}ensure_stage(root,binding)?;let raw=executor.run(&engine.docker("image",&["inspect",expected.reference,"--format",IMAGE_INSPECT_TEMPLATE]),root_path).await?;ensure_stage(root,binding)?;let image=verify_image(expected,&engine.platform,&raw.stdout)?;if image.config_id!=stored.config_id{return Err(LifecycleError::Image("paperless_repair_version_drift"));}}Ok(())}
fn replacement_receipt_bytes(journal:&PaperlessRepairJournal)->Result<Vec<u8>,LifecycleError>{let mut value:serde_json::Value=serde_json::from_slice(&journal.before_receipt_bytes).map_err(|_|LifecycleError::Receipt)?;let items=value.get_mut("containers").and_then(serde_json::Value::as_array_mut).ok_or(LifecycleError::Receipt)?;for member in &journal.members{let item=items.iter_mut().find(|item|item.get("service").and_then(serde_json::Value::as_str)==Some(member.service.as_str())&&item.get("id").and_then(serde_json::Value::as_str)==Some(member.prior_id.as_str())).ok_or(LifecycleError::Receipt)?;item["id"]=serde_json::Value::String(member.current_id.clone().ok_or(LifecycleError::Receipt)?);}serde_json::to_vec(&value).map_err(|_|LifecycleError::Io)}
fn repair_receipt(project:&str,volume_set_id:&str,members:&[RepairMember])->Result<PaperlessRepairReceipt,LifecycleError>{if members.len()!=3||members.iter().any(|item|item.current_id.is_none()){return Err(LifecycleError::Receipt);}Ok(PaperlessRepairReceipt{schema_version:1,operation:"paperless.repair".into(),project:project.into(),volume_set_id:volume_set_id.into(),services:members.iter().map(|item|PaperlessRepairServiceReceipt{service:item.service.clone(),action:item.action,prior_id:item.prior_id.clone(),current_id:item.current_id.clone().unwrap_or_default()}).collect()})}
async fn revalidate_bound_resources<E:ComposeExecutor>(executor:&mut E,engine:&Engine,root:&OwnedPaperlessRoot,binding:&EnvBinding,receipt:&StoredPaperlessInstallReceipt,journal:&PaperlessRepairJournal)->Result<(),LifecycleError>{for member in &journal.members{let id=member.current_id.as_deref().ok_or(LifecycleError::Receipt)?;let raw=inspect(executor,engine,root,binding,id).await?;let observed=verify_container(&image_for(receipt,&member.service)?,&journal.project,binding.port,&raw.stdout)?;if observed.id!=id||observed.image_id!=member.image_id{return Err(LifecycleError::UnownedOrMismatch);}}let generation=preflight_existing_volumes(executor,engine,&journal.project,root,binding).await?;if generation.as_deref()!=Some(journal.volume_set_id.as_str()){return Err(LifecycleError::UnownedOrMismatch);}Ok(())}
async fn require_ready<R:ReadinessVerifier>(home:&Path,credentials:&Credentials,readiness:&R,binding:&EnvBinding)->Result<(),LifecycleError>{let mut current=credentials.clone();current.paperless_url=Some(binding.origin.clone());if readiness.ready(home,&current).await{Ok(())}else{Err(LifecycleError::Readiness)}}
fn refuse_repair_custody(root:&OwnedPaperlessRoot)->Result<(),LifecycleError>{if read_uninstall_receipt(root)?.is_some(){return Err(LifecycleError::Command("paperless_repair_uninstall_present"));}for name in [paperless_purge::PURGE_CUSTODY_NAME,paperless_purge::PURGE_RECEIPT_NAME,ROTATION_JOURNAL_NAME,GENERATION_AUTH_NAME]{if read_optional_authority(root,name)?.is_some(){return Err(LifecycleError::Command("paperless_repair_custody_present"));}}Ok(())}
fn read_optional_authority(root:&OwnedPaperlessRoot,name:&str)->Result<Option<Vec<u8>>,LifecycleError>{let state=lifecycle_state_dir(root)?;match crate::skills::store::read_regular_file_bounded(&state,OsStr::new(name),&root.display.join(RECEIPT_DIR).join(name),RECEIPT_READ_LIMIT){Ok(bytes)=>Ok(Some(bytes)),Err(error) if error.root_cause().downcast_ref::<std::io::Error>().is_some_and(|io|io.kind()==std::io::ErrorKind::NotFound)=>Ok(None),Err(_)=>Err(LifecycleError::Receipt)}}
fn read_repair_journal(root:&OwnedPaperlessRoot)->Result<Option<PaperlessRepairJournal>,LifecycleError>{match read_optional_authority(root,REPAIR_JOURNAL_NAME)?{Some(bytes)=>serde_json::from_slice(&bytes).map(Some).map_err(|_|LifecycleError::Receipt),None=>Ok(None)}}
fn validate_repair_journal(
    journal: &PaperlessRepairJournal,
    receipt: &StoredPaperlessInstallReceipt,
    current: &[u8],
    root_path: &Path,
) -> Result<(), LifecycleError> {
    if journal.schema_version != 1
        || journal.operation != "paperless.repair"
        || journal.project != receipt.project
        || journal.volume_set_id != receipt.volume_set_id.clone().ok_or(LifecycleError::Receipt)?
        || journal.install_receipt_sha256 != digest(&journal.before_receipt_bytes)
        || journal.members.len() != 3
    {
        return Err(LifecycleError::Receipt);
    }
    let original: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&journal.before_receipt_bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&original, root_path)?;
    if original.project != journal.project
        || original.volume_set_id.as_deref() != Some(journal.volume_set_id.as_str())
        || original.containers.len() != 3
    {
        return Err(LifecycleError::Receipt);
    }
    for (member, stored) in journal.members.iter().zip(&original.containers) {
        if member.service != stored.service
            || member.prior_id != stored.id
            || member.image_id != stored.image_id
            || !exact_container_id(&member.prior_id)
            || member.current_id.as_deref().is_some_and(|id| !exact_container_id(id))
            || (member.action == PaperlessRepairAction::Healthy
                && member.current_id.as_deref() != Some(member.prior_id.as_str()))
            || (member.action == PaperlessRepairAction::Started
                && member.current_id.as_deref().is_some_and(|id| id != member.prior_id))
        {
            return Err(LifecycleError::Receipt);
        }
    }
    match journal.phase {
        RepairPhase::StartDispatched | RepairPhase::CreateDispatched => {
            let service = journal.effect_service.as_deref().ok_or(LifecycleError::Receipt)?;
            if !journal.members.iter().any(|member| member.service == service && member.current_id.is_none()) {
                return Err(LifecycleError::Receipt);
            }
        }
        RepairPhase::Prepared | RepairPhase::Bound | RepairPhase::ReceiptCommitDispatched | RepairPhase::Complete | RepairPhase::Held => {
            if journal.effect_service.is_some() { return Err(LifecycleError::Receipt); }
        }
    }
    if let Some(after) = journal.after_receipt_bytes.as_deref() {
        if replacement_receipt_bytes(journal)?.as_slice() != after { return Err(LifecycleError::Receipt); }
    }
    let valid_current = match journal.phase {
        RepairPhase::ReceiptCommitDispatched => current == journal.before_receipt_bytes || current == journal.after_receipt_bytes.as_deref().ok_or(LifecycleError::Receipt)?,
        RepairPhase::Complete => current == journal.after_receipt_bytes.as_deref().ok_or(LifecycleError::Receipt)?,
        RepairPhase::Prepared | RepairPhase::StartDispatched | RepairPhase::CreateDispatched | RepairPhase::Bound | RepairPhase::Held => current == journal.before_receipt_bytes,
    };
    if !valid_current {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}
fn digest(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn write_repair_journal_create_new(root:&OwnedPaperlessRoot,journal:&PaperlessRepairJournal)->Result<(),LifecycleError>{let state=lifecycle_state_dir(root)?;let bytes=serde_json::to_vec(journal).map_err(|_|LifecycleError::Io)?;crate::skills::store::atomic_write_private_child_create_new(&state,OsStr::new(REPAIR_JOURNAL_NAME),&root.display.join(RECEIPT_DIR).join(REPAIR_JOURNAL_NAME),&bytes).map_err(|_|LifecycleError::Io)?;ensure_bound(root)}
fn write_repair_journal(root:&OwnedPaperlessRoot,journal:&PaperlessRepairJournal)->Result<(),LifecycleError>{let state=lifecycle_state_dir(root)?;let bytes=serde_json::to_vec(journal).map_err(|_|LifecycleError::Io)?;crate::skills::store::atomic_write_private_child(&state,OsStr::new(REPAIR_JOURNAL_NAME),&root.display.join(RECEIPT_DIR).join(REPAIR_JOURNAL_NAME),&bytes).map_err(|_|LifecycleError::Io)?;ensure_bound(root)}
fn hold(root:&OwnedPaperlessRoot,journal:&mut PaperlessRepairJournal)->Result<(),LifecycleError>{journal.phase=RepairPhase::Held;journal.effect_service=None;write_repair_journal(root,journal)}
fn commit_receipt_exact(root:&OwnedPaperlessRoot,journal:&PaperlessRepairJournal)->Result<(),LifecycleError>{let expected=journal.after_receipt_bytes.as_ref().ok_or(LifecycleError::Receipt)?;let state=lifecycle_state_dir(root)?;let current=crate::skills::store::read_regular_file_bounded(&state,OsStr::new(RECEIPT_NAME),&root.display.join(RECEIPT_DIR).join(RECEIPT_NAME),RECEIPT_READ_LIMIT).map_err(|_|LifecycleError::Receipt)?;if current==*expected{return Ok(());}if current!=journal.before_receipt_bytes{return Err(LifecycleError::Receipt);}crate::skills::store::atomic_write_private_child(&state,OsStr::new(RECEIPT_NAME),&root.display.join(RECEIPT_DIR).join(RECEIPT_NAME),expected).map_err(|_|LifecycleError::Io)?;ensure_bound(root)}
fn remove_repair_journal(root:&OwnedPaperlessRoot)->Result<(),LifecycleError>{crate::skills::store::remove_child_file(&lifecycle_state_dir(root)?,OsStr::new(REPAIR_JOURNAL_NAME),&root.display.join(RECEIPT_DIR).join(REPAIR_JOURNAL_NAME)).map_err(|_|LifecycleError::Io)?;ensure_bound(root)}

#[cfg(test)]
#[path="paperless_repair_tests.rs"]
mod tests;
