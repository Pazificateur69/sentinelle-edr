//! Capteur ETW (Windows uniquement).
//!
//! VERIFICATION REQUISE AU 1er BUILD WINDOWS : les noms de methodes ferrisetw et
//! des proprietes ETW ci-dessous suivent la doc de ferrisetw 1.x, mais ce fichier
//! n'a jamais ete compile sous Windows depuis cette machine macOS. En cas d'erreur
//! de compilation, c'est ici : aligner sur les exemples de la version installee.
//!
//! Execution : binaire a lancer en Administrateur (providers noyau).
//!
//! AMELIORATION RECOMMANDEE (confirme par revue) : le provider manifeste
//! Microsoft-Windows-Kernel-Process utilise ici NE fournit PAS la ligne de
//! commande (d'ou l'enrichissement sysinfo, racy). Le *logger noyau classique*
//! (NT Kernel Logger, template Process_V2_TypeGroup1, flag EVENT_TRACE_FLAG_PROCESS)
//! fournit, lui, ImageFileName ET CommandLine nativement. Migrer vers la
//! KernelTrace de ferrisetw supprimerait la course sysinfo. A faire lors de la
//! validation sur VM Windows.

use crate::cmdline::cmdline_of;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use sentinelle_common::Event;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Provider Microsoft-Windows-Kernel-Process.
const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
/// WINEVENT_KEYWORD_PROCESS : indispensable pour Start/Stop.
const KEYWORD_PROCESS: u64 = 0x10;
const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;

/// Table PID -> image pour resoudre l'image du parent.
static PID_IMAGE: LazyLock<Mutex<HashMap<u32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Demarre la trace. `host` etiquette chaque evenement. `handler` recoit chaque
/// evenement. Bloquant jusqu'a l'arret de la trace.
pub fn run<F>(host: String, handler: F) -> anyhow::Result<()>
where
    F: Fn(Event) + Send + Sync + 'static,
{
    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .any(KEYWORD_PROCESS)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let _ = handle(record, locator, &host, &handler);
        })
        .build();

    // Nom de session UNIQUE par processus : les sessions ETW survivent à la mort du
    // process (une instance tuée laisse sa session enregistrée dans le noyau). Un nom
    // fixe provoquait alors `AlreadyExist` au lancement suivant. Le suffixe PID évite
    // la collision entre instances concurrentes ou après un arrêt brutal.
    let session = format!("sentinelle-kproc-{}", std::process::id());

    // start_and_process() demarre le traitement sur un thread dedie de ferrisetw
    // et renvoie la trace. On garde la trace vivante en bloquant ce thread.
    let _trace = UserTrace::new()
        .named(session)
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow::anyhow!("démarrage de la trace ETW : {e:?}"))?;

    // ponytail: park en boucle = garder la trace vivante sans busy-wait.
    loop {
        std::thread::park();
    }
}

fn handle<F>(
    record: &EventRecord,
    locator: &SchemaLocator,
    host: &str,
    handler: &F,
) -> anyhow::Result<()>
where
    F: Fn(Event),
{
    // Les erreurs ferrisetw n'implementent pas std::error::Error : on convertit a la main.
    let schema = locator
        .event_schema(record)
        .map_err(|e| anyhow::anyhow!("schema ETW : {e:?}"))?;
    let parser = Parser::create(record, &schema);

    match record.event_id() {
        EVENT_PROCESS_START => {
            let pid: u32 = parser
                .try_parse("ProcessID")
                .map_err(|e| anyhow::anyhow!("ProcessID : {e:?}"))?;
            let ppid: u32 = parser
                .try_parse("ParentProcessID")
                .map_err(|e| anyhow::anyhow!("ParentProcessID : {e:?}"))?;
            let image: String = parser.try_parse("ImageName").unwrap_or_default();

            let parent_image = {
                let mut map = PID_IMAGE.lock().unwrap();
                map.insert(pid, image.clone());
                map.get(&ppid).cloned().unwrap_or_default()
            };

            // Nom d'origine du PE (résistant au renommage) pour le masquerading.
            let original = sentinelle_sensor_proc::original_file_name_of(&image);
            let ev = Event::process_start(host, pid, ppid, &image, &parent_image)
                .with_cmdline(&cmdline_of(pid))
                .with_original_file_name(&original);
            handler(ev);
        }
        EVENT_PROCESS_STOP => {
            if let Ok(pid) = parser.try_parse::<u32>("ProcessID") {
                PID_IMAGE.lock().unwrap().remove(&pid);
            }
        }
        _ => {}
    }
    Ok(())
}
