CREATE SCHEMA IF NOT EXISTS openidconnect;

CREATE TABLE openidconnect.authorization_endpoint_parameters (
    id            UUID         NOT NULL,
    version       BIGINT       NOT NULL,
    date_created  TIMESTAMP    NOT NULL,
    last_updated  TIMESTAMP    NOT NULL,
    ui_locales    VARCHAR(255),
    display       VARCHAR(255),
    prompt        VARCHAR(255),
    scope         VARCHAR(255) NOT NULL,
    acr_values    VARCHAR(255),
    id_token_hint VARCHAR(255),
    login_hint    VARCHAR(255),
    max_age       BIGINT,
    created_by    VARCHAR(255) NOT NULL,
    response_type VARCHAR(255) NOT NULL,
    response_mode VARCHAR(255),
    PRIMARY KEY (id)
);
CREATE TABLE openidconnect.discovery_document (
    id                     UUID         NOT NULL,
    version                BIGINT       NOT NULL,
    date_created           TIMESTAMP    NOT NULL,
    last_updated           TIMESTAMP    NOT NULL,
    token_endpoint         VARCHAR(255) NOT NULL,
    end_session_endpoint   VARCHAR(255),
    userinfo_endpoint      VARCHAR(255),
    created_by             VARCHAR(255) NOT NULL,
    authorization_endpoint VARCHAR(255) NOT NULL,
    jwks_uri               VARCHAR(255) NOT NULL,
    issuer                 VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);
CREATE TABLE openidconnect.openid_connect_provider (
    id                                   UUID         NOT NULL,
    version                              BIGINT       NOT NULL,
    date_created                         TIMESTAMP    NOT NULL,
    last_updated                         TIMESTAMP    NOT NULL,
    discovery_document_url               VARCHAR(255),
    authorization_endpoint_parameters_id UUID         NOT NULL,
    client_id                            VARCHAR(255) NOT NULL,
    client_secret                        VARCHAR(255) NOT NULL,
    discovery_document_id                UUID         NOT NULL,
    created_by                           VARCHAR(255) NOT NULL,
    standard_provider                    BOOLEAN      NOT NULL,
    label                                VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);
CREATE TABLE openidconnect.openid_connect_token (
    id                         UUID         NOT NULL,
    version                    BIGINT       NOT NULL,
    date_created               TIMESTAMP    NOT NULL,
    expires_in                 BIGINT       NOT NULL,
    last_updated               TIMESTAMP    NOT NULL,
    access_token               TEXT         NOT NULL,
    not_before_policy          INTEGER,
    session_id                 VARCHAR(255) NOT NULL,
    token_type                 VARCHAR(255) NOT NULL,
    catalogue_user_id          UUID         NOT NULL,
    session_state              VARCHAR(255),
    scope                      VARCHAR(255) NOT NULL,
    refresh_token              TEXT,
    openid_connect_provider_id UUID         NOT NULL,
    id_token                   TEXT         NOT NULL,
    created_by                 VARCHAR(255) NOT NULL,
    refresh_expires_in         BIGINT,
    PRIMARY KEY (id)
);
CREATE
    INDEX authorizationEndpointParameters_created_by_idx ON openidconnect.authorization_endpoint_parameters(created_by);
CREATE
    INDEX discoveryDocument_created_by_idx ON openidconnect.discovery_document(created_by);
CREATE
    INDEX openidConnectProvider_created_by_idx ON openidconnect.openid_connect_provider(created_by);
ALTER TABLE openidconnect.openid_connect_provider
    ADD CONSTRAINT UK_hc3bjmsxauf094phcna8sdenr UNIQUE (label);
CREATE
    INDEX openidConnectToken_created_by_idx ON openidconnect.openid_connect_token(created_by);
ALTER TABLE openidconnect.openid_connect_token
    ADD CONSTRAINT UK4c34640a79eb7c33e398babc9f3c UNIQUE (catalogue_user_id, session_id);
ALTER TABLE openidconnect.openid_connect_provider
    ADD CONSTRAINT FKlwbbxbxnppnq16wir9lb2mmb5 FOREIGN KEY (authorization_endpoint_parameters_id) REFERENCES openidconnect.authorization_endpoint_parameters;
ALTER TABLE openidconnect.openid_connect_provider
    ADD CONSTRAINT FK5gelp5vivw7w8ruishcfow0dk FOREIGN KEY (discovery_document_id) REFERENCES openidconnect.discovery_document;
ALTER TABLE openidconnect.openid_connect_token
    ADD CONSTRAINT FKqdl6u342dsg6xnmruqdg3lnaq FOREIGN KEY (catalogue_user_id) REFERENCES security.catalogue_user;
ALTER TABLE openidconnect.openid_connect_token
    ADD CONSTRAINT FKpap35aly7ud3siorrhvclyc7n FOREIGN KEY (openid_connect_provider_id) REFERENCES openidconnect.openid_connect_provider;

