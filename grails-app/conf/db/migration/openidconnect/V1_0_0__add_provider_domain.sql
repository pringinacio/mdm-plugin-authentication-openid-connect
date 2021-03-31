CREATE SCHEMA IF NOT EXISTS openidconnect;


CREATE TABLE openidconnect.openid_connect_provider (
    id                                     UUID         NOT NULL,
    version                                INT8         NOT NULL,
    date_created                           TIMESTAMP    NOT NULL,
    access_token_request_url               VARCHAR(255) NOT NULL,
    last_updated                           TIMESTAMP    NOT NULL,
    base_url                               VARCHAR(255) NOT NULL,
    authentication_request_parameters_json TEXT         NOT NULL,
    created_by                             VARCHAR(255) NOT NULL,
    openid_connect_provider_type           VARCHAR(255) NOT NULL,
    authentication_request_url             VARCHAR(255) NOT NULL,
    access_token_request_parameters_json   TEXT         NOT NULL,
    label                                  VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);
CREATE
index openidConnectProvider_created_by_idx ON openidconnect.openid_connect_provider (created_by);
ALTER TABLE if EXISTS openidconnect.openid_connect_provider ADD CONSTRAINT UK_hc3bjmsxauf094phcna8sdenr UNIQUE (label);