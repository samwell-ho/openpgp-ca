// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use reqwest;
use reqwest::{Response, StatusCode};

use crate::restd::oca_json::{Certificate, ReturnError, ReturnJSON};

pub struct Client {
    client: reqwest::Client,
    uri: String,
}

impl Client {
    pub fn new<S: Into<String>>(uri: S) -> Self {
        Client {
            client: reqwest::Client::new(),
            uri: uri.into(),
        }
    }

    async fn map_result(
        resp: Result<Response, reqwest::Error>,
    ) -> Result<ReturnJSON, ReturnError> {
        match resp {
            Ok(o) => match o.status() {
                StatusCode::OK => {
                    let resp = o.json::<ReturnJSON>().await.unwrap();

                    return Ok(resp);
                }
                StatusCode::BAD_REQUEST => {
                    let resp = o.json::<ReturnError>().await.unwrap();

                    return Err(resp);
                }
                _ => panic!("unexpected status code {}", o.status()),
            },
            Err(e) => {
                panic!("error {}", e);
            }
        }
    }

    pub async fn check(
        &self,
        cert: &Certificate,
    ) -> Result<ReturnJSON, ReturnError> {
        let cert_json = serde_json::to_string(&cert).unwrap();

        let resp = self
            .client
            .get(&format!("{}/certs/check", &self.uri))
            .body(cert_json)
            .send()
            .await;

        Client::map_result(resp).await
    }
}
