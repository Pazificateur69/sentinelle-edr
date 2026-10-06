//! Garde par jeton partagé pour les routes d'ACTION (kill, simulate).
//!
//! Le mTLS protège le transport agent↔serveur, mais PAS les routes HTTP de la
//! console : sans ça, quiconque joint le port peut pousser un `kill`. On exige
//! donc un jeton sur les routes destructrices.
//!
//! Ouvert par défaut : si `SENTINELLE_TOKEN` n'est pas défini (ou vide), la garde
//! laisse passer — la démo locale et l'usage mono-poste sur 127.0.0.1 ne changent
//! pas. Dès que le jeton est défini, les clients doivent l'envoyer dans l'en-tête
//! `X-Sentinelle-Token`.
//!
//! ponytail: lecture d'env à chaque requête — négligeable à cette échelle, et ça
//! évite un état partagé ; passer à un `OnceLock` si le volume l'exige un jour.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// En-tête portant le jeton d'action.
pub const TOKEN_HEADER: &str = "x-sentinelle-token";

/// Middleware axum : exige un jeton valide quand `SENTINELLE_TOKEN` est défini.
pub async fn require_token(req: Request, next: Next) -> Response {
    match std::env::var("SENTINELLE_TOKEN") {
        Ok(expected) if !expected.is_empty() => {
            let provided = req
                .headers()
                .get(TOKEN_HEADER)
                .and_then(|v| v.to_str().ok());
            if sentinelle_common::token_ok(&expected, provided) {
                next.run(req).await
            } else {
                (StatusCode::UNAUTHORIZED, "jeton d'action invalide ou absent").into_response()
            }
        }
        // Pas de jeton configuré → ouvert (démo / mono-poste localhost).
        _ => next.run(req).await,
    }
}
